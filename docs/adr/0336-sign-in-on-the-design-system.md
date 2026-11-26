# 0336: Sign-in on the design system

## Status

Accepted (26 Nov 2026). A slice of the UI overhaul workstream ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)), on the design system of [ADR 0335](0335-design-system-for-the-app-and-the-console.md). Behaviour doesn't change.

## Context

The app's sign-in screen, its two-factor steps ([ADR 0094](0094-totp-second-factor.md)) and the app lock ([ADR 0078](0078-client-biometric-app-lock.md)) were the first thing people saw, and the last screens still dark on a light phone before reaching the restyled chat. They took fixed colours from the dark-only `colors` object, a plain stack of boxes with no card, square-ish buttons, an error as a line of red text, and no scrolling, so five single sign-on buttons pushed the Connect button off a small phone. A request that never reached the server showed the browser's own words ("Failed to fetch").

## Decision

### One frame for every sign-in step

`components/SignInParts.tsx` holds what the steps share, built only from the tokens:

- `SignInFrame`: the SuperBot mark, a title and a line under it, in a centred raised card (radius `xl`, the `card` shadow) at most 440 px wide. Below 520 px the card's edge and shadow go, so a phone's whole screen is the card. It scrolls and moves for the keyboard, and sets the status bar for the scheme.
- `Field` (a labelled box with an accent focus ring, named by its label for screen readers), `PrimaryButton` (the one accent pill on a step, with a spinner while busy), `TextButton`, a `Divider` ("or") and a `Notice`: a soft danger card announced as an alert for what went wrong, or a soft accent card for what's been done for you (an invite code filled in).

The sign-in screen (server URL, single sign-on, code or password), the two-factor check and set-up, the recovery codes and the lock screen all use it, and follow the device's light or dark setting. The boot spinner before them does too, so nothing flashes dark first.

### Provider buttons, and Apple's colours

Single sign-on buttons (Microsoft Entra, Google, GitHub, any OIDC provider, SAML through a broker) are full-width outlined pills in the server's order, as before. Apple's Human Interface Guidelines allow its button only in black or white, so it is the one colour outside the tokens: `APPLE_BUTTON` in `LoginScreen.tsx`, black with white text in light mode and white with black text in dark, where it used to be white everywhere. Its wording stays "Sign in with Apple".

### Errors people can act on

`signInErrorMessage` passes the server's messages through unchanged, says "Can't reach a SuperBot server at <url>. Check the server URL and your connection." when the request never got there, and says the server had a problem for a bare 5xx. Errors sit just above the button that caused them.

### Shared parts in screens not yet restyled

The QR code and recovery codes (`MfaSetupView`, `RecoveryCodes`) are themed for sign-in. Settings' two-factor card is still dark-only until its slice, so it holds them to a dark `ThemeScope` there. The QR code keeps a white ground in both schemes, since authenticator apps need dark modules on light to scan.

## Alternatives considered

- **Brand logos on the provider buttons**: familiar, but Google's and Microsoft's marks must be shown in their own colours, more colours outside the tokens and more artwork to keep right. Text-only pills match the calm look; logos can follow if people miss them.
- **Apple's colours from the palette (`text` on `bg`)**: close, but warm near-black isn't the black Apple's guidelines ask for.
- **A card on phones too**: a card inside a small screen wastes its width and looks nested; the same parts without the edge read better.
- **Hiding the server URL when the web build is served by the server**: tidier, but a change in behaviour; it stays a visible field.

## Tests

- `SignInParts.test.tsx`: the card on wide windows and none on a phone, both schemes, a field's focus ring and name, the primary button's accent and busy state, and danger notices announced as alerts while info notices aren't.
- `LoginScreen.test.tsx`: Apple's button is black in light mode and white in dark while the others and Connect follow the theme; an unreachable server, the server's own refusal and an ended session each show as an alert; `signInErrorMessage` for network, 5xx, 4xx and other errors. The existing provider, invite and two-factor tests pass unchanged.
- `TwoFactorCard.test.tsx`: recovery codes in settings stay dark on a light device. The app lock tests pass unchanged.

## Consequences

- Sign-in, two-factor and the lock screen leave the dark-only list; a light phone is light from the first screen to the chat.
- New sign-in or connect steps use `SignInFrame` and its parts.
- The console's sign-in page (`web/login.html`) and the setup wizard's first run are still to restyle in this slice.
