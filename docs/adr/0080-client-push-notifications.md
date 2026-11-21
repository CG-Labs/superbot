# 0080: Push notifications in the client

## Status

Accepted (21 Nov 2026). M3 client item "push notifications (routine completions, approvals)" ([#36](https://github.com/CG-Labs/superbot/issues/36), [roadmap](../ROADMAP.md)). Builds on approval notifications ([ADR 0061](0061-approval-notifications.md)), routines ([ADR 0047](0047-disabled-users-routines.md)) and sessions ([ADR 0012](0012-users-sessions-rbac.md)). The Expo client is the primary interface ([ADR 0027](0027-expo-primary-hermes-default.md)).

## Context

Email and webhooks (ADR 0061) reach people about pending approvals when no app is open. People on phones expect a notification instead, and also want to hear when a scheduled routine has finished. A push must reach only the person it is for, say nothing a locked phone shouldn't show, and stop the moment that person signs out. Self-hosted servers must keep working unchanged, with no paid account and no app store.

## Decisions

### Off unless an operator turns it on

- `PUSH_PROVIDER=expo` in botd's environment turns push on. Unset (or `off`), the server sends nothing, `/api/me/push` answers that push is off, and the app says so. Any other value stops botd at start.
- The provider is **[Expo push](https://docs.expo.dev/push-notifications/sending-notifications/)**: one HTTPS endpoint for both platforms, free, and no Apple or Google keys on the server. botd posts at most 100 messages a request and keeps only Expo's error codes, since its messages quote the token.
- `EXPO_ACCESS_TOKEN` is optional: set it (in `.env` or with `botctl secret set`) only if the Expo project turns on "enhanced push security". No Bot gets it.
- Providers sit behind one `Provider` trait (`server/src/notify/push.rs`). Direct APNs or FCM would be another one later.

### One phone per session

- `PUT /api/me/push` `{token, platform: "ios" | "android", approvals?, routines?}` registers this session's phone, replacing any phone it had. `GET` shows it; `DELETE` removes it. Bots, the shared password and loopback dev have no session, so they get no phone. Registering needs Write: read-only people can't decide approvals or run routines. Anyone may remove theirs.
- The token is **sealed at rest** (like other sealed fields) and never returned or logged. A hash keeps it unique: if the same phone registers in another session (someone else signs in on it), it **moves** there, and the last person stops getting pushes on it.
- A row lives with its session (`push_devices`, `ON DELETE CASCADE`). **Signing out, an admin revoking the session, revoking all of a person's sessions and disabling them all delete it.** At send time botd also checks that the session is still live (idle and max age) and the person is active, so a phone left on an expired session gets nothing even before pruning.
- Each person keeps at most 20 phones; registering more drops the oldest.

### What is pushed, and to whom

- **Approvals:** push is another channel of the notifier (ADR 0061). It reaches the phones of the people who can answer: the Bot's owner and operators who may approve and still have Operate access. It uses the same delay (answered approvals send nothing), the same per-Bot throttle and digest. It doesn't follow the email or webhook switches: each person chooses on their phone.
- **Routines:** when a routine's run finishes, the person it ran for hears of it: the routine's author, else the Bot's owner. Only runs that actually started count, since refusals already say why in chat. Access is checked again at send time. Several finishes of one Bot within 10 minutes go as one push ("Ledger finished 3 scheduled routines.").
- **Nothing sensitive:** a push says only "Approval needed / *Bot* is waiting for your approval." or "Routine finished / *Bot* finished a scheduled routine." No command, tool, reason, routine name or output. Its data carries only ids and the in-app path (`/home?approval=<id>` or `/home?bot=<id>`). The app fetches the rest after sign-in and App lock.
- **Limits:** at most 30 pushes per person per hour, across both kinds. Each person can turn either kind off on their phone.
- **Audit:** `push.registered` (with `moved`), `push.updated`, `push.unregistered` (`reason`: `user` or `provider_gone`), and each send as `notification.sent` / `notification.failed` with `channel: push`. Tokens never appear. A token Expo says is gone (`DeviceNotRegistered`) is deleted.

### In the app

- A **Push notifications** card in Settings. Off by default. Turning it on asks the phone for permission (Android gets its `default` channel first, as Android 13+ requires), gets the Expo push token for the build's EAS project, and registers it. Two switches choose approvals and routines.
- **Tapping a push** opens the inbox on the approval, or the Bot's chat. Only those two places, built from the ids; the payload's URL is never followed, and pushes that aren't SuperBot's are ignored. A tap that opens the app works too. Sign-in keeps the link (as ADR 0061 did for `?approval=`), and App lock still comes first.
- **Web and the desktop app** get no push: the card says to use the phone app, and `src/pushDevice.web.ts` never loads the native module. Web Push is left for later.

## What an operator adds

Nothing is published to an app store, and no paid account is needed.

1. On the server: `PUSH_PROVIDER=expo` in `.env`, then restart botd. Its startup line says `push through expo`. Optionally `EXPO_ACCESS_TOKEN` (see above).
2. Whoever builds the app (with EAS, a free Expo account): set the build's real EAS project id in `app.json` → `expo.extra.eas.projectId` (the repo ships a placeholder, and the card says when a build has none). Add the push credentials EAS asks for: an FCM V1 service account key for Android, and an APNs key for iOS (APNs needs an Apple Developer account, which builds for iPhones need anyway). These stay with EAS, not botd.
3. Expo Go and simulators can't receive these pushes; use a development or internal build on a real phone.

## Consequences

- Self-hosted servers are unchanged until an operator sets `PUSH_PROVIDER`.
- Pushes go through Expo's service, so it sees the Bot's name, the title and the target device, but nothing a Bot asked. Operators who don't want that leave push off.
- Each push follows its session, so a lost phone is cut off by signing out or by an admin revoking the session.
- Not in this slice: Web Push, direct APNs/FCM, richer pushes (like approving from the notification), and refreshing a token the phone rotates without opening Settings.
