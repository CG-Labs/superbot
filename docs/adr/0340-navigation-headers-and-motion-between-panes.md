# 0340: Navigation, screen headers and motion between panes

## Status

Accepted (26 Nov 2026). The rest of the navigation and shell slice of the UI overhaul ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)), on the design system of [ADR 0335](0335-design-system-for-the-app-and-the-console.md), whose first slice did the sidebar and home layout. Behaviour doesn't change.

## Context

After [ADR 0337](0337-a-shared-kit-for-settings-and-admin-screens.md) most screens pushed over home used `PageHeader`, but the way around them still differed screen by screen:

- Each of the ten routes (settings, plan, secrets, team, policy, users, roles, service accounts, the audit log, access review) wrote its own back handler and its own safe-area frame.
- The admins-only notices ("Only admins can manage users.") had no header, so the screen lost its title and its back pill.
- On phones, a list's detail (a user, a role, a service account, an audit event) opened in a modal whose "back" was a full-width row with its own padding: a fixed 48-point top gap on three screens and a safe area on the fourth.
- The root stack still laid every screen on the dark-only canvas with a light status bar, so a light phone showed dark text on light screens under light status-bar icons.
- Nothing moved: Bots and chat swapped in one frame on phones, a picked item's detail replaced the last one at once, and web had no transition between screens at all.

## Decision

### One header, one way back

- `PageHeader` (`components/ui.tsx`) stays the one header: a back pill named for where it goes, the title read as the screen's header, an optional quiet subtitle, and its actions grouped on the right. The pill is text-coloured rather than accent-coloured, since ADR 0335 keeps the accent for primary actions, and it gets a larger touch area (`hitSlop`, 36-point minimum height). `BackButton` is the pill on its own.
- `components/Shell.tsx` holds the navigation around it:
  - `goBack` / `useGoBack` go back a screen, or to home when there is none (a link or a reload), the rule every route already followed, now in one place.
  - `RouteScreen` is every pushed screen's frame: the safe area on the canvas.
  - `RouteNotice` is the admins-only notice with the screen's header above the same words and the same "Back to Bots" link.
  - `DetailSheet` is a phone's full-screen detail: the shared header with a back pill to its list ("‹ Users", read as "Back to users"), a safe area, and the system back closing it, as before.
- The not-found screen leaves the Expo template's colours and takes the same frame and header.
- The root stack lays screens on the theme's canvas, and the status bar follows the scheme (dark icons on light, light on dark) on every screen, not just home.

### Motion between panes

- `PaneTransition` brings a pane in with a short fade and a 12-point shift over the tokens' `base` duration (200 ms), easing out. On phones, chat slides in from the right over the Bot list and the list from the left; on wide windows a picked user's, role's, service account's or audit event's detail fades up in its pane; and on web, where the native stack has no push animation, each pushed screen fades in. A pane at rest has no transform or opacity, so nothing positioned inside it is affected.
- Native pushes keep the platform's own animation.
- **Reduced motion**: `useReducedMotion` (`src/motion.ts`, shared with the empty, loading and error states slice) follows iOS's and Android's setting and `prefers-reduced-motion` on web. With it on, `useMotion` gives every token duration as 0, panes just appear, the stack's push becomes `none`, and the detail sheets, the new-Bot sheet and the sign-up request sheet appear without sliding.

### Not in this slice

The chat header's back button and the approvals, Bot details and screen viewer sheets are part of home, which the first slice did, and the empty, loading and error states slice (PR #401) is changing their buttons and modal motion. They stay as they are here.

## Alternatives considered

- **The native stack's own header (`headerShown: true`)**: platform back gestures and titles for free, but a second header beside `PageHeader` in every screen, with platform looks that don't follow the tokens, and nothing on web. The stack keeps `headerShown: false`, and screens keep their own header.
- **Reanimated for the transitions**: it is installed, but a fade and a shift over 200 ms need nothing beyond React Native's `Animated` with the native driver, and Reanimated's layout animations need more setup in tests and on web.
- **Animating panes as they leave too**: smoother, but each pane would have to stay mounted until it finished, which changes when screens mount and unmount (and so when they load). Only entry is animated.
- **Animating the switch across the 800-point breakpoint**: resizing a window isn't navigating, so the home transition is keyed on the phone's pane, not the layout.

## Tests

- `components/__tests__/Shell.test.tsx`:
  - the header in light and dark (title, subtitle and back pill colours), the back pill's touch area, and no header text when there is no title;
  - going back a screen, or home (or another fallback) when there is none;
  - the admins-only notice with its header and both ways back;
  - the route frame in both schemes, at rest without motion styles;
  - the detail sheet's header, its back pill and the system back, and its slide, or none with reduced motion;
  - token durations, or 0 with reduced motion;
  - a new pane coming in over the `base` duration with a fade and a shift, then resting without a transform; no animation at all with reduced motion; the first pane coming in only when asked;
  - the stack's canvas and status bar per scheme, and no push animation with reduced motion.
- `AuditScreen.test.tsx`: the admins-only notice keeps the "Audit log" header, and its back goes home after a reload.
- `RolesAdmin.test.tsx`: on a phone, a role opens over the list with a "Back to roles" pill that closes it.
- Every existing test passes unchanged, including the audit log's "Back to the audit log" detail test and the headers' back labels.

## Consequences

- A new screen pushed over home uses `RouteScreen`, `PageHeader` and `useGoBack`; a list with a phone-width detail uses `DetailSheet`; anything that swaps panes uses `PaneTransition` instead of its own animation.
- Motion everywhere takes its durations from `tokens.json` through `useMotion`, so the reduce-motion setting is honoured in one place.
- The slice is done: every screen pushed over home, light and dark, has the same header and the same way back.
