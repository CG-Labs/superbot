# 0337: A shared kit for the settings and admin screens

## Status

Accepted (26 Nov 2026). The settings and admin portal slice of the UI overhaul ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)), on the design system of [ADR 0335](0335-design-system-for-the-app-and-the-console.md). Behaviour doesn't change.

## Context

After ADR 0335 the chat screen and the sidebar followed the device's light or dark setting, but settings, plan, secrets, team, policy and the admin screens (users, roles, service accounts, the audit log, access review) were still dark-only. About twenty files each had their own header, card, button, tag and input styles, written with fixed colours and sizes that had drifted apart: radius 10, 12, 14 or 16, white or blue primary buttons, four tag colour schemes. Restyling them one by one onto the tokens would have left the same drift in token form.

## Decision

- **One kit**: [`apps/client/components/ui.tsx`](../../apps/client/components/ui.tsx) holds the shared look as `kit(t)`, a style set made once per scheme from the tokens: page root and column, header, card and card title, group heading, rows with hairline separators, text tones, tinted notices, inputs and the pill search field, buttons (outlined, primary, danger, ghost), tags in each status tone, and the modal backdrop and sheet. It also has `PageHeader` (a back pill, the title as a header, and actions), `Card`, `Spinner` and `usePlaceholder`.
- **Screens keep their style names**: each screen's `themedStyles` picks from `kit(t)` under the names it already used (`card: k.card`, `btn: { ...k.btn, alignSelf: "flex-start" }`), adding tokens only for its own layout. The JSX barely changes, so behaviour and tests stay as they were, and every screen gets the same corners, spacing and colours. No hex colour or loose font size is left in these files; the one exception is the two-factor QR code, which stays white because scanners need dark modules on white.
- **Layout**: content sits in rounded raised cards on the warm canvas, under small uppercase group headings ("This device", "Your account"; "Built in", "Custom"). Lists are hairline-separated rows inside a card. On wide windows the list pane sits on the sidebar's surface colour beside a centred detail column. Primary actions use the one accent colour (ADR 0335); a picked choice in `Chips` is filled with the text colour (dark on light, light on dark), which reads as selected without spending the accent; destructive actions are soft red pills.
- **Shared parts in screens not yet restyled**: `Chips` and the two-factor setup views now follow the scheme. Bot details and the sign-in screen are still dark-only, so Bot details wraps itself, and sign-in wraps the two two-factor views it shows, in a dark `ThemeScope`, as ADR 0335 asks. Each scope goes when its screen is restyled.
- **The console**: CSS only, outside the generated token block. Tables become rounded cards with a quiet uppercase header row, hairline rows and a hover tint. The header keeps the brand and your name on one row, with the tabs on a single scrollable row below them when the window is too narrow for both. Fields, buttons, tags, cards and modals use the token spacing and type, and the settings groups are set apart by a hairline. The setup wizard and `login.html` keep their styles for the onboarding slice.

## Alternatives considered

- **Components for everything (`<Button>`, `<Row>`, `<Field>`)**: tidier JSX, but every `Pressable` with its labels, roles, states and handlers would be rewritten across twenty files, which is where behaviour changes slip in. Shared styles under the screens' own names give the same look with far less churn. New screens can still use `PageHeader` and `Card`.
- **A theme per screen**: what the mechanical conversion first produced. It moved the drift onto tokens without removing it.
- **Accent fill for picked chips**: louder, and against ADR 0335's rule that the accent is for primary actions, the send button, unread dots and the selected Bot.
- **New console markup (wrapping each settings group in a card)**: a nicer grouping, but `app.js` builds much of the console's HTML, and changing markup there is a behaviour risk this slice doesn't need.

## Tests

- `components/__tests__/ui.test.tsx`: `PageHeader` shows the title as a header and goes back, takes its own back text and label, has no back button without `onBack`, and holds the back button when asked; a `Card` takes the light or dark palette from the device setting; `kit` is made once per scheme; a picked chip is filled with the text colour and reported checked, and stays dark inside a dark scope.
- `RolesAdmin`, `PlanView`, `SecretsView`, `TeamView` and `PolicyEditor` tests gain a check that the title is a header and back works. Every existing settings and admin test passes unchanged.

## Consequences

- New settings and admin UI takes its look from `kit(t)` and `PageHeader` rather than its own styles.
- On a phone or browser in light mode, settings and the admin screens are now light; Bot details, sign-in and onboarding stay dark until their slices.
- A change to the shared look (say, card corners) is one edit in `ui.tsx` for the app and one in `web/styles.css` for the console.
