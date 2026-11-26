# 0345: Empty, loading and error states, and accessibility, on every screen

## Status

Accepted (26 Nov 2026). Finishes two slices of the UI overhaul workstream ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)), "Empty, loading and error states" and "Accessibility and dark-mode polish", which [ADR 0339](0339-empty-loading-and-error-states.md) did for the chat screen and the shell. This ADR takes the same components and rules to every other screen of the Expo app, on the design system of [ADR 0335](0335-design-system-for-the-app-and-the-console.md) and the settings kit of [ADR 0337](0337-a-shared-kit-for-settings-and-admin-screens.md). Behaviour doesn't change. Screen headers, back navigation and motion between panes belong to ADR 0340 (open beside this change); the console's sign-in and setup wizard and the landing page have their own slices.

## Context

After ADR 0339, settings, plan, secrets, team, the approval policy, the admin screens (users, roles, service accounts, the audit log, access review), Bot settings and the sign-in cards still showed a bare spinner while they loaded, a red line of raw error text (`HTTP 500`, `Failed to fetch`) when they failed, often with no way to try again, and one grey line for an empty list. Some never recovered: two-factor, a role's holders and a service account's tokens spun for good when their request failed, and a team that failed to load said "You aren't on a team". Bot settings, the new-Bot sheet, the approvals sheet and the screen viewer were still dark-only: they used the old `colors` object and fixed hex values and held their themed parts in a dark `ThemeScope`, so a phone in light mode showed them dark. Many buttons, switches and fields had no names, and card titles weren't headings.

## Decision

### Loading

- **`PageSkeleton`** (`Skeleton.tsx`) stands in for a settings or admin screen while it loads: a heading and a card or two of rows in the screen's column, one busy element with a name ("Loading your plan"). Lists and cards use `ListSkeleton` ("Loading users", "Loading push notifications", "Loading tokens").
- **`BusyDots`** is a small busy mark with a name for an action that's running, such as a save on the team screen; it replaces the spinner in that screen's header.
- Busy buttons keep their label and say what's running ("Adding…", "Approving…", "Creating…"), disabled and marked busy, instead of swapping the label for a spinner. Sign-in's primary button keeps its label and is marked busy.
- **`Spinner`** in `components/ui.tsx` now renders `PageSkeleton`. Only the route files use it, while a screen waits for the saved session; those files belong to ADR 0340's change, so they keep the name until it lands, and it is marked deprecated.
- The keeper panel in Bot settings still shows nothing while it loads, as before: most Bots have no service account to hand over to, and a skeleton that then disappears would only flash.

### Errors

- Every screen words its errors with `friendlyError` and `errorText` (ADR 0339): the server's own messages pass through, bare status codes and network failures become sentences, and a failed load says what failed first ("Couldn't load users. Can't reach the server…").
- A screen with nothing to show without its data (plan, team, policy, access review, roles, service accounts) shows `ErrorState` with "Try again". Where the rest of the screen still works (the secrets form, the audit log's filters, a list that loaded before a refresh failed) and inside cards (push, notifications, data residency, two-factor, role requests, the hash chain, a user's sessions and Bot access, routines, logins), a failed load is an `InlineError` with "Try again" beside what's there. A load failure is kept apart from an action failure, so only loads offer a retry. Failed actions (save, delete, export, sign-off, create) are an `InlineError` without one.
- The ones that spun or misled now recover: two-factor's status, a role's holders and a service account's tokens show an error with "Try again", and a team that didn't load says so instead of "You aren't on a team".

### Empty states

Empty lists use `EmptyState` (compact) with a monochrome glyph and the next step in words: no secrets, users, matches, rules, routines, suggested prompts, custom roles, teams, service accounts, tokens, kept Bots, sign-offs or audit events, and not being on a team. No new actions were added; where a list sits beside its own "Add" or "New" control, the words point to it. Lists meant to show nothing when empty (waiting sign-ups, role requests) still show nothing.

### Light and dark everywhere

- Bot settings (with its routine and prompt editors, the keeper and teammate-login panels and suggested prompts), the new-Bot sheet, the approvals sheet and the screen viewer's chrome move onto `themedStyles`, `kit(t)` and the tokens, and lose their dark `ThemeScope`s. Sheets sit on the sidebar's surface over the scheme's overlay; primary buttons use the accent, destructive ones the soft red pill; the picked schedule preset is filled with the text colour, like `Chips`.
- The full-screen screen viewer on phones and the web page's background before the app draws use the tokens' canvas colour in each scheme.
- The old `colors` object keeps only `bgMain`, for the root stack's backdrop, which ADR 0340's shell replaces; then it can go. `ThemeScope` stays for parts that must hold one scheme, and no screen uses it.
- Fixed colours remain only where they aren't the app's: a Bot's avatar art, Apple's black or white sign-in button, the two-factor QR code's white ground (ADR 0337) and the black letterbox around a Bot's remote screen, which frames that screen's own pixels.

### Accessibility

- **Names, roles and states**: every button, switch and text field on these screens has a name ("Bot name", "Hide from sidebar", "Search people", "Turn on two-factor authentication", "Disable Alex", "Join Alpha"), rows say which is selected, harness choices are a radio group, the new Bot's colours are named ("Colour Teal"), busy buttons say they're busy, and errors are alerts.
- **Headings**: card and section titles are headings (`role="heading"`), so screen readers can move between them; the screen's own title stays the header, as ADR 0340 sets it.
- **Focus order** follows the reading order: no screen reorders its content visually. The web build's keyboard focus ring (ADR 0339) covers every control on these screens.
- **Dynamic type**: text keeps scaling; glyph-only buttons (close, ✓) cap their glyph at 1.3× so it stays in its circle, and the screen viewer's bar grows with its text instead of a fixed height.
- **Reduced motion**: the skeletons and busy dots hold still when the device asks; the admin screens' sheets are ADR 0340's.

## Alternatives considered

- **Editing the route files and the screen headers here**: the route files' spinner and the screens' headers are in ADR 0340's change, which is open beside this one. Turning `Spinner` into the page skeleton changes what those files show without touching them. The `Spinner` imports left unused in four admin screens sit on lines that change too; they go when the two changes meet.
- **`ErrorState` for every failed load**: simpler, but it would hide forms and lists that still work (adding a secret, the audit log's filters, a list loaded before a refresh failed). A full-screen error only where there's nothing else to show keeps every screen as useful as it was.
- **A skeleton for the keeper panel and the sign-up requests**: they show nothing when there's nothing to do; a skeleton first would flash on most Bots and for most admins.
- **New colour tokens for the remote screen's letterbox**: a token is a CSS custom property in the console too, for a colour that is black by definition.

## Tests

- `src/__tests__/theme.test.tsx`: for light and dark, a table of every screen and the token pairs its text, tags, notices and buttons use, each at 4.5:1 (3:1 for faint hints); every text style in `kit(t)` checked against the grounds it sits on or its own fill; skeleton blocks visible on raised cards; no file in `app/` or `components/` imports the dark-only colours (except the root layout, until ADR 0340) or holds a dark `ThemeScope`; fixed hex colours only in the files named above; every Bot colour has a name.
- `components/__tests__/StateViews.test.tsx`: `PageSkeleton` and `BusyDots` are one busy element with a name, the page skeleton holds still under reduced motion, and `Spinner` renders the page skeleton.
- Each screen's tests cover its skeleton by name, its error with "Try again" reloading, kept data beside a failed refresh, failed actions as alerts without a retry, its empty state's heading, and the new names, headings and states. Bot settings, its editors and panels, the new-Bot sheet, the approvals sheet and the screen viewer are rendered in light and dark and checked against `themes.light` and `themes.dark`. Every existing test passes, with text expectations updated where a message gained "Couldn't load …" or an empty line became a heading.

## Consequences

- Every screen of the app follows the device's light or dark setting; there are no dark-only screens left.
- New screens use `PageSkeleton`, `ListSkeleton`, `ErrorState`, `InlineError`, `EmptyState` and `friendlyError`, and the contrast table in `theme.test.tsx` gains a row for each new screen.
- When ADR 0340's change and this one have both merged, the route files move from `Spinner` to `PageSkeleton`, the four unused `Spinner` imports go, and `colors` is deleted.
