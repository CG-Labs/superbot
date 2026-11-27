# App Store and Google Play listings

What the SuperBot app needs for its store listings ([#45](https://github.com/CG-Labs/superbot/issues/45), slice 1): the listing text, screenshots, privacy answers, and the `eas submit` settings. Nothing here has been sent to a store. Publishing needs the owner: the EAS project ([#11](https://github.com/CG-Labs/superbot/issues/11)), TestFlight and Play internal builds ([#38](https://github.com/CG-Labs/superbot/issues/38)), and the store accounts. Choices are in [ADR 0349](../adr/0349-store-listings-and-privacy-answers.md).

## What's here

| File | What it is |
|------|------------|
| [`app-store.config.json`](app-store.config.json) | App Store listing: name, subtitle, promotional text, description, keywords, categories, age rating answers, URLs, release settings. In the [EAS Metadata](https://docs.expo.dev/eas/metadata/) format, so `eas metadata:push` can send it. |
| [`google-play.json`](google-play.json) | Google Play listing: name, short and full description, category, contact details, URLs, graphics. Play has no EAS Metadata, so this is typed into the Play Console. |
| [`app-privacy.md`](app-privacy.md) | Answers for Apple's App Privacy questions, from what the code sends. |
| [`data-safety.md`](data-safety.md) | Answers for Google Play's Data safety form, from the same facts. |
| [`screenshots.md`](screenshots.md) | The screenshot plan, the draft screenshots, and how to make them again. |
| [`apps/client/eas.json`](../../apps/client/eas.json) | `submit.production`: where `eas submit` sends builds. |

`npm run store:check` (in `apps/client`, run by CI) checks the text against each store's limits, the submit profile, and the screenshots' sizes. `npm run store:ready` also fails while any owner placeholder is left; run it before the first submission.

## Owner placeholders

Values only the owner can give are marked `OWNER_TODO` (or use the `owner-todo.invalid` domain, which can never resolve). Fill in each before submitting:

| Value | Where | Notes |
|-------|-------|-------|
| Apple team id | `eas.json` → `submit.production.ios.appleTeamId` | 10 characters, from the Apple Developer account's Membership page. |
| App Store Connect app id | `eas.json` → `submit.production.ios.ascAppId` | The number in the app's App Store Connect URL, once the app record exists. |
| Play service account key | `GOOGLE_SERVICE_ACCOUNT_KEY_PATH` environment variable | Path to the key's JSON file on the machine that runs `eas submit`. Never commit the key; `.gitignore` refuses `*service-account*.json` and `*.p8`. Or upload it to EAS once (`eas credentials`) and drop the field. |
| Legal name | `app-store.config.json` → `apple.copyright` | The publisher's legal name, after the year. |
| Privacy policy URL | both listings | A public page made from the [privacy policy template](../security/privacy-policy-template.md) after legal review; needs the published site ([#44](https://github.com/CG-Labs/superbot/issues/44)). |
| Support and marketing URLs | both listings | Any public pages; the docs portal's install guide works for support. |
| Contact email | `google-play.json` → `contactEmail` | Shown publicly on the Play listing. |
| Account deletion URL | `google-play.json` → `accountDeletionUrl` | Play requires one: a page saying how to ask for an account and its data to be deleted. |

App Store sign-in details for review (a contact name, phone and email, and a demo account) go straight into App Store Connect and never into the repo.

## Submitting (slice 2, with the owner)

1. Finish #11 and #38: a real EAS project id in `app.json`, and builds through TestFlight and Play internal testing.
2. Create the app records: in App Store Connect (bundle id `com.cglabs.superbot`), and in the Play Console (package `com.cglabs.superbot`).
3. Fill in the placeholders above, then `npm run store:ready`.
4. Answer the privacy questions from [`app-privacy.md`](app-privacy.md) and [`data-safety.md`](data-safety.md).
5. Upload the screenshots ([plan](screenshots.md)) and the Play graphics (`apps/client/assets/brand/store/`).
6. `eas build -p all --profile production`, then `eas submit -p ios --profile production` and `eas submit -p android --profile production`. iOS builds land in TestFlight; send the version for review from App Store Connect. Android builds go to the production track as a draft, released from the Play Console.
7. Optionally `eas metadata:push` to send the App Store text from `app-store.config.json` (EAS Metadata is in beta: check the result in App Store Connect).

## For App Review

Suggested review notes (App Store Connect → App Review Information → Notes; Play Console → App access):

> SuperBot is the app for a SuperBot server, which runs AI agents ("Bots") on their own computers. It needs an account on a server. We have set up a demo server for review: enter its address on the sign-in screen, then the sign-in code below. The demo Bots can chat, show their screen, and ask for approval before risky steps. App lock (Settings) uses Face ID; push notifications need the server to have them on, which the demo server does.

The demo server, its address and a sign-in code are owner actions: give the address and code in the review fields, not in the notes.

## Review risks to settle in slice 2

These came up while writing the answers. None blocks the listing material, but each could fail a review.

- **Account deletion (App Store 5.1.1(v), Play's account deletion policy).** The app has no "delete my account". Accounts are made by admins, but single sign-on can add a new person on their first sign-in, which may count as account creation. Either add an in-app way to ask for deletion, or show App Review that accounts are created by the organization. Play needs the deletion URL either way.
- **Buying plans on iPhone (App Store 3.1.1).** When a server sells plans, the Plan screen opens Stripe's checkout in the browser. App Review may reject that for digital plans. Billing is off unless the server has Stripe keys, so the review demo server should leave it off; selling plans on iOS needs its own decision.
- **Demo server (App Store 2.1, Play's app access).** Reviewers need a working server and account for the whole review.
- **Sign-in options (App Store 4.8).** A server can offer Google or GitHub sign-in. Apps that use only an organization's own accounts are exempt; the demo server should offer a sign-in code (and Sign in with Apple, if it offers any third-party sign-in).
- **Age rating.** The Bot's screen is a full computer with a browser, so "unrestricted web access" is answered yes. That gives the app the highest age rating.
- **New Play developer accounts.** Personal Play accounts made since November 2023 must run a closed test with at least 12 testers for 14 days before production. Organization accounts don't.
- **First Play upload.** The Play API (and so `eas submit`) can't create an app: upload the first build by hand in the Play Console.
- **Encryption export answer.** `app.json` sets `ios.config.usesNonExemptEncryption: false`: the app uses only the system's HTTPS and hashing, which are exempt. The owner confirms this when App Store Connect asks.
