# 0335: A design system for the app and the admin console

## Status

Accepted (26 Nov 2026). The first slice of the UI overhaul workstream ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)). The owner asked for a serious upgrade of how SuperBot looks, in the direction of Grok Bot's apps: clean, warm, minimal and chat-first. This ADR sets the design system every later slice uses, and restyles the chat screen and the app shell with it. Behaviour doesn't change.

## Context

The Expo app ([ADR 0027](0027-expo-primary-hermes-default.md)) and the admin console ([ADR 0032](0032-console-admin-only.md)) were dark-only, with cool greys. Every screen took fixed colours from one `colors` object in `src/theme.ts`, and many components wrote more hex values straight into their styles. The console had its own copy of the same colours in `web/styles.css`, and the landing page in `site/assets/site.css`. Spacing, corner radii and type sizes were chosen screen by screen. There was no light mode, even though phones and browsers ask for one. The result looked unfinished: a sidebar that took half the window, chat bubbles for every message, a hard rule above the message box, and nothing to see in an empty chat.

What we want is the look and feel of the Grok Bot assistant apps, without copying them: a warm neutral palette with one accent colour, generous whitespace, rounded cards and pill buttons, crisp system type, polished light and dark modes, subtle motion and friendly empty states. "Grok" stays out of our code and names ([ADR 0002](0002-name.md)), so the tokens and components are named for what they are.

## Decision

### One source of tokens

[`apps/client/src/tokens.json`](../../apps/client/src/tokens.json) is the design system's single source:

- **Colour**, by role, for `light` and `dark`: `bg` (the canvas), `surface` (the sidebar), `raised` and `elevated` (cards, the composer), `hover`, `selected`, `userBubble`, `border`, `borderStrong`, `text`, `textMuted`, `textFaint`, `accent` with `accentText`, `accentSoft`, `accentBorder` and `onAccent`, `danger`, `warning` and `success` each with a soft tint, `codeBg`, `overlay` and `shadow`. Names say what a colour is for, never what it looks like, so a later palette change touches one file.
- **Spacing** on a 4-point scale (`xxs` 2 to `xxxl` 48), **radii** (`sm` 8, `md` 12, `lg` 16, `xl` 22, `pill`), **type** (sizes 12 to 28 with line heights, four weights, the system sans stack and a monospace stack), **shadows** per scheme (`card`, `pop`), **motion** durations (120, 200 and 320 ms) and **layout** widths (a 300 px sidebar, a 760 px chat column).

The palette is warm off-white and warm charcoal rather than pure white and black. The one accent is SuperBot blue, kept from the brand mark ([docs/brand.md](../brand.md)) so icons, splash and the app agree; it fills primary buttons, the send button, unread dots and the selected Bot, and nothing else is coloured except status (danger, warning, success).

### In the app

`src/theme.ts` turns the tokens into a typed `Theme` and adds:

- `useTheme()`, which follows the device's light or dark setting (`useColorScheme`), and `themedStyles(factory)`, a hook that builds a component's `StyleSheet` once per scheme, so restyled components cost nothing extra on each render.
- `ThemeScope`, which holds everything inside it to one scheme. Screens not yet restyled are still dark-only; where one shows a restyled part (the approvals sheet shows approval cards), it wraps that part in a dark scope, so nothing turns light inside a dark sheet.
- The old `colors` object stays for screens not yet restyled, now taking its neutrals from the dark palette, so every screen moves to the warm greys at once, and the old blue, red, amber and green stay as they were, since those screens pair them with fixed white text.

### In the admin console

`npm run tokens` (in `apps/client`) writes the same tokens into a marked block at the top of `web/styles.css` as CSS custom properties (`--c-bg`, `--space-md`, `--radius-pill`, …), light by default and dark under `prefers-color-scheme: dark`. The console's own variables now point at them, and its hard-coded dark colours are replaced, so the console follows the browser's light or dark setting too. `npm run tokens:check` fails CI when the block and the JSON disagree, as `brand:check` does for the icons. Its sign-in page (`web/login.html`) and the landing page keep their styles until their own slices.

### The first slice: the chat screen and the shell

- **Shell**: the sidebar is a fixed 300 px on wide windows (it used to take half the window), with the SuperBot name, a pill search field, the main Bot as a raised card, Bots as rounded rows, and the rest (hidden Bots, approvals, plan, secrets, team, settings and, for admins, an "Admin" group) in the same scroll, so a long admin list no longer squeezes out the Bots. Your name is pinned at the bottom. The status bar follows the scheme while the home screen is shown.
- **Chat**: messages sit in a centred 760 px column. A Bot's words are plain text on the canvas, with no bubble; yours sit in a soft rounded bubble on the right. Choice cards are raised cards with rounded options, the handoff banner is a soft accent card, approval cards have a warning edge, and the model and effort pickers are small pills above a floating rounded composer with a round send button. An empty chat greets you ("Say hello to …"), and the screen without a Bot open says what to do.
- **Accessibility**: body text, muted text and links meet WCAG AA (4.5:1) on every background in both schemes, faint text (timestamps, hints) meets 3:1, and text on the accent and on tinted cards meets 4.5:1; a test checks every pair. Pale Bots get a thin outline in light mode so they don't vanish. Buttons that were glyphs only (new Bot, sign out, back, send) have accessible names.

Everything does what it did: the same actions, labels, roles and routes.

### The slices that follow

Tracked in the workstream's issue, each restyling more screens onto the tokens and removing them from the dark-only list: navigation and screen headers; settings and the admin portal (in the app and the console); onboarding and sign-in (the app's sign-in screen and `web/login.html`); the landing page (`site/`, which then takes the tokens too); empty, loading and error states across the app; and an accessibility and dark-mode pass that ends the dark-only `colors` object.

## Alternatives considered

- **A styling library (NativeWind, Tamagui, Restyle)**: theming and variants for free, but a new build step or runtime, a second way to style beside the existing `StyleSheet`s, and a migration of every screen at once. Typed tokens and a small hook do what we need with what we have.
- **Following the system scheme everywhere at once**: the right end state, but most screens have fixed dark colours, and turning them light without restyling each one would make text unreadable. The dark scope and the dark-only `colors` object keep every screen readable while slices land.
- **Tokens in TypeScript, with the CSS generated from it**: one file either way, but Node can't import TypeScript without a build step in CI, and JSON is easy for any tool (and a later Rust check) to read.
- **A new accent colour**: tempting for a fresh look, but the brand mark and store art are blue, and one colour across the icon and the app is part of looking finished.
- **A custom typeface**: the system fonts (San Francisco, Roboto, Segoe UI) are crisp, load instantly and need no licence review ([docs/brand.md](../brand.md)).

## Tests

- `src/__tests__/theme.test.tsx`: light and dark have the same colour and shadow names; every text pair above meets its WCAG contrast in both schemes; `useTheme` follows the device setting (light when it has none) and a `ThemeScope` holds its children to its scheme; the dark-only `colors` take the dark palette's neutrals.
- `scripts/tokens.test.mjs`: every colour becomes a custom property in light and in dark, and the generator replaces only its own block, idempotently. `npm run tokens:check` runs in the client workflow.
- `ChatView.test.tsx` gains tests that the send button sends the trimmed message and nothing when the box is empty, that an empty chat greets you, and that the screen with no Bot open has no message box; the existing chat, sidebar, approvals and Markdown tests pass unchanged except for the code font, which now comes from the tokens.

## Consequences

- New UI work uses `useTheme`/`themedStyles` and token names, not hex values; a restyled screen leaves the dark-only list.
- Until the last slice, a phone or browser in light mode shows the chat and the sidebar light, and the screens not yet restyled (Bot details, settings, the admin screens, sign-in) dark.
- A palette or spacing change is one edit to `tokens.json` plus `npm run tokens`, and reaches the app and the console together.
