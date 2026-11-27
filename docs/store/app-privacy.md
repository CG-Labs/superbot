# App Store privacy answers

Answers for App Store Connect → App Privacy, from what the app sends on `main` (checked against the code, 27 Nov 2026). Data safety for Google Play is in [`data-safety.md`](data-safety.md); both rest on the same facts. Why the answers are written for the managed service is in [ADR 0349](../adr/0349-store-listings-and-privacy-answers.md).

## How the app handles data

- **One destination.** The app talks to the SuperBot server the person signs in to, and nothing else, apart from three steps the person starts: single sign-on opens their organization's sign-in page in the system browser ([`src/sso.ts`](../../apps/client/src/sso.ts)); turning on push notifications asks Expo's push service for a token ([`src/pushDevice.ts`](../../apps/client/src/pushDevice.ts)); and on a server that sells plans, buying one opens Stripe's page in the browser ([`src/billing.ts`](../../apps/client/src/billing.ts)).
- **No third-party SDKs that collect data.** No analytics, advertising, crash reporting or attribution SDK. The native modules are Expo's own (secure store, local authentication, notifications, file system, sharing, web browser) and React Native's ([`package.json`](../../apps/client/package.json)).
- **On the device.** The server address and session token are in the iOS keychain ([`src/auth.ts`](../../apps/client/src/auth.ts)). Chats are kept in memory only. Face ID and Touch ID run in iOS: the app gets a yes or no, never biometric data ([`src/localAuth.ts`](../../apps/client/src/localAuth.ts), [ADR 0078](../adr/0078-client-biometric-app-lock.md)). An exported audit log goes to the share sheet, from the app's cache ([`src/saveCsv.ts`](../../apps/client/src/saveCsv.ts)).
- **No photos, camera, microphone, contacts, location or files.** The app asks for none of these permissions and has no picker. The only permission prompts are Face ID (App lock) and notifications.

## Answers

**Do you or your third-party partners collect data from this app?** Yes.

**Tracking.** No data is used to track people. The app has no advertising, shares nothing with data brokers, and doesn't link its data with other companies' data. No `NSUserTrackingUsageDescription`, no App Tracking Transparency prompt.

Every collected type is **linked to the person** (it lives on their account on the server) and **used for App Functionality** only. Apple counts security and fraud prevention as App Functionality.

| Category | Data type | Collected | Why, and where in the code |
|----------|-----------|-----------|----------------------------|
| Contact Info | Name | Yes | The account's display name, from single sign-on or set by an admin; admins also type names when adding people ([`users` table](../../server/src/db.rs), `/api/users`). |
| Contact Info | Email Address | Yes | The account's email, for sign-in, approval and billing emails ([ADR 0061](../adr/0061-approval-notifications.md)); admins type others' emails to invite them (`/api/team/invites`). |
| Contact Info | Phone Number, Physical Address, Other Contact Info | No | Never asked for. |
| User Content | Other User Content | Yes | What people send their Bots: chat messages and answers to choice cards (`/api/bots/:id/messages`), routines, prompts, approval decisions, notification settings, and personal secrets for their Bots (`/api/me/secrets`, stored sealed). Typing into a Bot's screen after **Take over** goes to the Bot's computer. |
| User Content | Emails or Text Messages, Photos or Videos, Audio Data, Gameplay Content, Customer Support | No | No email or SMS access, no media pickers, no microphone, no in-app support form. Chat with a Bot is user content, not an email or text message. |
| Identifiers | User ID | Yes | The account id the server gives each person, sent back on every request through the session. |
| Identifiers | Device ID | Yes | Only when the person turns on push notifications: Expo's push token for the phone, and the installation id Expo's library sends to get it ([`expo-notifications`](https://docs.expo.dev/versions/latest/sdk/notifications/)). The server stores the token sealed with the session and deletes it on sign-out ([ADR 0080](../adr/0080-client-push-notifications.md)). Not the advertising identifier: the app never reads it. |
| Purchases | Purchase History | Yes | Only on a server that sells plans: the person's plan and subscription status (`/api/billing`). Payment details are typed on Stripe's page, never in the app. |
| Usage Data | Product Interaction | Yes | The server's audit log records what each account did and when, for security ([data flows](../security/data-flows.md)), and which chats are read (`/api/bots/:id/read`). |
| Usage Data | Other Usage Data | Yes | Runs, model tokens and storage each person used, to apply plan limits (`/api/me/usage`). |
| Usage Data | Advertising Data | No | No advertising. |
| Financial Info | Payment Info, Credit Info, Other Financial Info | No | Payments happen on Stripe's page in the browser, outside the app. |
| Location | Precise, Coarse | No | No location permission. The server records the IP address of each sign-in for security, but never turns it into a location. |
| Sensitive Info | Sensitive Info | No | The app never asks for it. |
| Contacts | Contacts | No | No address book access. |
| Health & Fitness | Health, Fitness | No | |
| Browsing History | Browsing History | No | The app has no browser of its own. A Bot's screen shows the Bot's own computer; what is opened there belongs to that computer, counted above as user content. |
| Search History | Search History | No | The sidebar's search filters Bots on the phone and is never sent. |
| Diagnostics | Crash Data, Performance Data, Other Diagnostic Data | No | No crash or performance reporting in the app. The server's optional error tracker never holds a user, prompt or body ([ADR 0113](../adr/0113-service-dashboards-and-error-reporting.md)). |
| Surroundings, Body | Environment Scanning, Hands, Head | No | |
| Other Data | Other Data Types | No | |

## Notes for the owner

- **Third parties that receive data for the service.** AI model providers (prompts and replies, from the server), Expo (push tokens and the Bot's name in a push), Stripe (billing), the email provider, and the hosting provider. They process data for the service and are listed in the [subprocessor list](../security/subprocessors.md). Apple doesn't ask for them by name, but the privacy policy must name them.
- **Privacy manifest.** Expo's modules ship their own `PrivacyInfo.xcprivacy` with their required-reason API uses, which EAS Build merges. The app adds nothing of its own; `ios.privacyManifests` in `app.json` can if a later change needs it.
- **Keep these answers true.** Adding an analytics or crash SDK, a media picker, location, or anything that sends more to the server changes these answers: update this page and App Store Connect in the same PR.
