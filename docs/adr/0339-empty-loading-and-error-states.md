# 0339: Empty, loading and error states, and accessibility on the chat screen and shell

## Status

Accepted (26 Nov 2026). A slice of the UI overhaul workstream ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)), on the design system of [ADR 0335](0335-design-system-for-the-app-and-the-console.md). It covers the chat screen, the shell and the lists they show (the sidebar's Bots, approvals, a Bot's routines, the screen viewer). Settings, the admin screens, sign-in and onboarding are restyled in their own slices and take these components there.

## Context

The app showed a bare spinner while anything loaded, a blank or dark screen while it started, and raw error text (`HTTP 500`, `Failed to fetch`) in alert dialogs or not at all: a failed send lost the message, a failed stop said nothing, and routines that didn't load looked like "No routines yet". Nothing said when the live connection dropped; the `connected` flag went false on the first error and never came back. Empty lists were one grey line. Screen readers heard unnamed Bot rows and an unnamed chat header, and nothing respected reduced motion.

## Decision

### Shared state components

All on the tokens, following the scheme or a `ThemeScope`, in `apps/client/components/`:

- **`EmptyState`**: a glyph or art (a Bot's avatar), a title read as a heading, one line of help, and at most a primary and a secondary action (`PillButton`). `compact` fits it into the sidebar and panels.
- **`ErrorState`** fills a screen or pane that couldn't load: what failed as the title, why in plain words, and "Try again". **`InlineError`** is the same in one line inside a list. A retry that returns a promise keeps the button busy ("Trying…") until it settles.
- **Skeletons** (`Skeleton.tsx`): `ChatSkeleton`, `ListSkeleton` and `AppSkeleton` (the shell's outline while the app starts) replace spinners. Each is one element screen readers hear as busy, with a name ("Loading messages"), not a list of shapes. `ThinkingDots` replaces the spinner beside "Working…".
- **Toasts** (`useToast`, provided at the root): one at a time at the top, error, success or info, with an optional action; errors and toasts with an action stay 6 seconds, others 4. Outside a provider, errors fall back to the dialog as before. Modals keep dialogs, since a toast at the root would sit behind them.
- **`ConnectionBanner`**: "You're offline" when the browser says so, "Reconnecting…" once the live event stream has been down for 1.5 seconds, and a "Back online" toast when it returns. The stream now reports each time it is up (`connectSse`'s `onLive`), so the flag comes back after a reconnect. Native apps have no network module, so there a drop shows as reconnecting; adding one would mean a new native dependency for little gain.

### Errors in plain words

`friendlyError` (`src/errors.ts`) keeps the server's own messages, which are already written for people, and turns bare status codes and network failures into sentences ("Can't reach the server. Check your connection and try again."). `errorText` puts what failed first: "Couldn't load routines. Can't reach the server…".

### Where they're used

- Chat: a skeleton while history loads (only when nothing is cached), an error with a retry if it fails, "No Bots yet" with "New Bot" when there are none, the greeting as an `EmptyState`, and toasts for failed sends, answers and stops. A failed send's words go back in its own Bot's box (or wait, per Bot and per signed-in session, until that box is empty), and Retry sends to that Bot. Once the words are back in a box, or you resend them yourself, Retry goes away, so a message is never sent twice; signing out forgets them.
- Shell: the boot skeleton instead of a spinner, the connection banner, and toasts instead of dialogs for the console and setup links. The sidebar's empty list says what to do: make a first Bot, make more beside the main one, clear a search that matches nothing, or where hidden Bots go.
- Approvals: "You're all caught up". Routines: a skeleton, an inline error with a retry (they used to fail silently as an empty list), and an explanation when there are none. The screen viewer: a skeleton while it starts and an error with "Try again" that asks at once instead of waiting for the next automatic retry.
- The app has no file list yet; when one lands it uses `EmptyState` the same way.

### Accessibility on the chat screen and shell

- **Names and states**: Bot rows say the Bot's name and what's waiting ("Ada, needs you on its screen, unread") and which is open (selected); the chat header names the Bot and its harness and opens its details; Stop and Cancel name the Bot; choice options say which was picked and that the rest are closed; Approvals says how many are waiting; close buttons have names. "Working…", errors, toasts and the banner are live regions (announced on iOS, which has none).
- **Focus**: the web build adds one rule for a 2 px ring in the scheme's accent on whatever has keyboard focus (`:focus-visible`, so not on a mouse click); text fields keep their own focus styles (the composer's from ADR 0335).
- **Reduced motion**: `useReducedMotion` follows the device (and `prefers-reduced-motion` on web); skeletons and dots hold still, toasts appear without sliding, the chat jumps to the end instead of scrolling, and modals open without sliding. On web a CSS rule also stops animations and smooth scrolling.
- **Dynamic type**: text scales with the system setting as before; glyph-only buttons (back, send, new Bot, sign out, close) cap their scaling so the glyph stays inside its circle, and rely on their names.
- **Contrast**: the theme test now also checks the focus ring (3:1, WCAG 1.4.11) on every background in both schemes and on the dark-only screens, the colours each state uses (4.5:1), and that skeleton blocks are visible where they load.

## Alternatives considered

- **A network module (`@react-native-community/netinfo`)** for offline on phones: a native dependency and a new build for a banner the event stream already drives.
- **Toasts everywhere, including in modals**: they'd render behind native modals; a portal per modal is more machinery than the few errors there need.
- **Spinners with a label**: better than nothing, but skeletons keep the layout still and read as faster; screen readers hear the same busy name either way.
- **A focus style on every `Pressable`**: React Native's `focused` state is also set by a mouse click, so the ring would show after every click; `:focus-visible` is what browsers use for exactly this.

## Tests

- `components/__tests__/StateViews.test.tsx`: empty and error states (heading, alert, actions, busy retry), pill buttons, skeletons as one busy element and holding still under reduced motion, the thinking dots hidden from screen readers, the banner's texts and grace period, and toasts (polite and assertive, durations, actions, dismissing, replacing, iOS announcements and the dialog fallback).
- Chat, sidebar, approvals, details panel and screen viewer tests cover each state above and the new names and states; `src/__tests__/errors.test.ts`, `motion.test.tsx` and `webA11y.test.ts` cover the helpers, and `theme.test.tsx` the new contrast pairs.

## Consequences

- New screens use these components and `friendlyError` instead of spinners, blank screens or raw error text, and `useReducedMotion` for any motion.
- The settings, admin and sign-in slices adopt them as they restyle those screens; their spinners stay until then.
