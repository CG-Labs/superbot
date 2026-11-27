# Google Play Data safety answers

Answers for Play Console → App content → Data safety, from what the app sends on `main` (checked against the code, 27 Nov 2026). They rest on the same facts as the [App Store answers](app-privacy.md), which give the evidence for each data type. Why they are written for the managed service is in [ADR 0349](../adr/0349-store-listings-and-privacy-answers.md).

## Data collection and security

| Question | Answer | Why |
|----------|--------|-----|
| Does your app collect or share any of the required user data types? | Yes | Accounts, chats and the rest below go to the SuperBot server. |
| Is all of the user data collected by your app encrypted in transit? | Yes | Release builds for Android don't allow plain HTTP: Expo turns cleartext traffic on only in debug builds (checked with `expo prebuild`: `usesCleartextTraffic` is set only in `src/debug` and `src/debugOptimized`). So the app reaches servers over HTTPS only. |
| Do you provide a way for users to request that their data is deleted? | Yes | An admin or the provider erases a person's data ([ADR 0102](../adr/0102-erasing-a-users-data.md)); the account deletion URL (an owner placeholder in [`google-play.json`](google-play.json)) says how to ask. |

**Shared: none.** Play doesn't count data sent to service providers that process it for the developer, or data a person chooses to send. AI model providers, Expo's push service, Stripe, the email and hosting providers are service providers ([subprocessors](../security/subprocessors.md)); single sign-on and Stripe's checkout are steps the person starts.

**Ephemeral: none.** Each type below is stored on the server.

## Data types

| Category | Data type | Collected | Required or optional | Purposes |
|----------|-----------|-----------|----------------------|----------|
| Personal info | Name | Yes | Required | App functionality, Account management |
| Personal info | Email address | Yes | Required | App functionality, Account management |
| Personal info | User IDs | Yes | Required | App functionality, Account management, Fraud prevention, security, and compliance |
| Personal info | Address, Phone number, Race and ethnicity, Political or religious beliefs, Sexual orientation, Other info | No | | |
| Financial info | Purchase history | Yes | Optional (only on a server that sells plans) | App functionality, Account management |
| Financial info | User payment info, Credit score, Other financial info | No | | Payments are on Stripe's page in the browser. |
| Messages | Other in-app messages | Yes | Required | App functionality |
| Messages | Emails, SMS or MMS | No | | |
| App activity | App interactions | Yes | Required | App functionality, Fraud prevention, security, and compliance |
| App activity | Other user-generated content | Yes | Optional (routines, prompts, personal secrets, notification settings) | App functionality |
| App activity | In-app search history, Installed apps, Other actions | No | | The Bot search filters on the phone and is never sent. |
| Device or other IDs | Device or other IDs | Yes | Required | App functionality |
| Location | Approximate, Precise | No | | |
| Web browsing | Web browsing history | No | | |
| Photos and videos, Audio files, Files and docs, Calendar, Contacts | All | No | | No permissions and no pickers. |
| Health and fitness | All | No | | |
| App info and performance | Crash logs, Diagnostics, Other app performance data | No | | No crash or performance reporting in the app. |

## Why these choices

- **Other in-app messages** is what the person sends their Bots (chat messages and answers to choice cards). Play's own example for this type is chat content.
- **App interactions** covers the server's audit log of what each account did, and which chats are read, kept for security. Usage counted against plan limits (runs, tokens, storage) is included here too.
- **Device or other IDs** is Expo's push token and the installation id Expo's library sends to get it, once a person turns on push notifications. It's marked required rather than optional because Firebase Cloud Messaging, which push uses on Android, can make its own token when the app starts once the app is built with FCM ([#36](https://github.com/CG-Labs/superbot/issues/36)). If the build turns FCM's automatic start off, it can be marked optional.
- **Purchase history** is the plan and subscription status a server that sells plans keeps. Optional, since most servers sell nothing.

## Other App content answers

| Section | Answer |
|---------|--------|
| Ads | No ads. |
| App access | Sign-in needed: give the demo server's address and a sign-in code (owner, see [For App Review](README.md#for-app-review)). |
| Target audience | 18 and over. A work tool, not designed for children. |
| Content rating (IARC) | Category: Utility, Productivity, Communication, or Other. No violence, sexual content, profanity, drugs or gambling. Users can interact or share content: yes (Bots can be shared with a team). Unrestricted internet access: yes (a Bot's screen is a full computer with a browser). Shares the person's location: no. Digital purchases: only on a server that sells plans. |
| News app, Health apps, Financial features, Government app | No. |
| Data deletion | The account deletion URL in [`google-play.json`](google-play.json). |
| Permissions | Internet, biometrics (App lock), notifications, vibration. `app.json` blocks the storage and draw-over-other-apps permissions the app doesn't use, so they never reach the listing. |
