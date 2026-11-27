# 0349: Store listings and privacy answers

## Status

Accepted (27 Nov 2026). Slice 1 of [#45](https://github.com/CG-Labs/superbot/issues/45) (App Store and Play production release): the store listings, screenshots, privacy and data-safety answers, and the `eas submit` settings. Slice 2, submitting, waits on the owner ([#11](https://github.com/CG-Labs/superbot/issues/11), [#38](https://github.com/CG-Labs/superbot/issues/38), store accounts, a public privacy URL). Builds on the Expo client ([ADR 0027](0027-expo-primary-hermes-default.md)), push notifications ([ADR 0080](0080-client-push-notifications.md)) and the privacy policy template ([security pack](../security/privacy-policy-template.md)). The material is in [`docs/store/`](../store/README.md).

## Context

The stores need listing text within their limits, screenshots at set sizes, answers about what the app collects, and, for `eas submit`, ids from the owner's accounts. None of it existed: `eas.json` had an empty `submit.production`. The material must stay true as the app changes, and must never hold a credential, since the repo is public.

The privacy answers turn on who "collects". The app talks only to the SuperBot server a person signs in to. On a self-hosted server, that is the person's own organization, not the app's publisher. On the managed service, it is the publisher. One store listing covers both.

## Decisions

### Answer as the managed service

The App Store and Play answers count everything the app sends to its server as collected by the developer, linked to the person, for app functionality. That is true for the managed service and over-states nothing a store would object to for self-hosted servers. Answering "not collected" because some servers are self-hosted would be wrong for the managed service, and the stores treat an under-stated label as a policy breach. Where a type is unclear, it is declared: Expo's push token and installation id as Device ID, and on Play as required rather than optional, since Firebase can start on its own once the app is built with FCM. Nothing is shared or used for tracking: the third parties involved (AI model providers, Expo, Stripe, email and hosting) process data for the service.

The answers cite the code they rest on ([App Store](../store/app-privacy.md), [Play](../store/data-safety.md)), so a change that sends more can be checked against them.

### Listings as data, checked in CI

- The App Store listing is in the [EAS Metadata](https://docs.expo.dev/eas/metadata/) format (`docs/store/app-store.config.json`), named by `submit.production.ios.metadataPath`, so `eas metadata:push` can send it. EAS Metadata covers only the App Store, so the Play listing is a plain JSON file beside it, typed into the Play Console.
- `npm run store:check` (`apps/client/scripts/store.mjs`, in the client workflow) checks each field against the store's limit (characters, keywords in bytes joined with commas), the URLs, that the names start with the installed name, that App Store text names no other platform (guideline 2.3.10), the submit profile's shape, and every screenshot's size against what its store takes. `npm run store:ready` fails while any owner placeholder is left.

### Owner values are placeholders, credentials never in the repo

- Values only the owner has are `OWNER_TODO_*` strings, or URLs on `owner-todo.invalid`, a domain that can't resolve. `store:ready` lists them.
- The Play service account key is `$GOOGLE_SERVICE_ACCOUNT_KEY_PATH`, read from the environment where `eas submit` runs. The check refuses a literal path there, and for any App Store Connect API key field. `.gitignore` refuses `*.p8` and `*service-account*.json`.
- Android submissions go to the production track as a draft, so the owner releases each from the Play Console. iOS builds land in TestFlight, and are sent for review from App Store Connect; the listing releases by hand after approval, in phases.

### Screenshots from the web build, with made-up data

`npm run store:screenshots` serves the web build beside a stand-in for the server's API and drives headless Chrome over the DevTools protocol at the 6.9" iPhone, 13" iPad and Play phone sizes. No new dependency: Node 22's WebSocket and a local Chrome. The same stand-in (`--serve`) lets a simulator or emulator sign in, for native captures. The drafts are committed, labelled as made-up data; the plan says to replace any that differ from the native app before submitting.

### Two settings in `app.json`

- `ios.config.usesNonExemptEncryption: false`. The app uses only the system's HTTPS and hashing, which are exempt from export rules, so App Store Connect doesn't ask on every build.
- `android.blockedPermissions` removes `SYSTEM_ALERT_WINDOW` and the storage permissions that Expo's template adds. The app writes only to its own cache and shares through the share sheet, so it uses none of them, and they would otherwise show on the Play listing.

## Consequences

- The listing material is ready for the owner; slice 2 is filling in the placeholders and submitting.
- A change that makes the app send more (an analytics or crash SDK, a picker, location) must update both answer pages in the same PR.
- Store reviews may still raise what the [review risks](../store/README.md#review-risks-to-settle-in-slice-2) list: in-app account deletion, buying plans on iPhone, the demo server, sign-in options, the age rating.
- Not in this slice: localized listings, caption overlays on screenshots, Play tablet screenshots, and turning FCM's automatic start off.
