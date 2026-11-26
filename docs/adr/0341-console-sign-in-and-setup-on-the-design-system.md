# 0341: The console's sign-in and the setup wizard on the design system

## Status

Accepted (26 Nov 2026). Finishes the onboarding and sign-in slice of the UI overhaul ([roadmap](../ROADMAP.md#ui-overhaul-grok-bot-aligned)), on the design system of [ADR 0335](0335-design-system-for-the-app-and-the-console.md), after the app's sign-in ([ADR 0336](0336-sign-in-on-the-design-system.md)). Behaviour doesn't change.

## Context

The web sign-in page (`web/login.html`, served at `/login` for everyone who signs in on the web) was the last page still dark-only with its own hex colours: a bare stack of boxes, square-ish buttons, an error as a line of red text, and a white Apple button on a dark page. It can't use the console's style sheet, because `/console/styles.css` is for admins only and people aren't signed in yet. So when ADR 0335 moved the console onto the tokens, this page stayed behind.

The setup wizard (the console's Setup tab, [ADR 0034](0034-onboarding-wizard.md)) is where a new server's first admin lands after signing in. ADR 0337 restyled the rest of the console and left the wizard for this slice: a title squeezed into a toolbar, step buttons, and the step's content loose on the page. If `/api/setup` failed, the browser's own words ("Failed to fetch") showed as grey text, with nothing to do next.

## Decision

### The sign-in page

- **Same tokens, its own styles**: `npm run tokens` now writes the generated token block into `login.html`'s `<style>` as well as into `web/styles.css`, and `npm run tokens:check` fails CI when either is out of date. The page keeps its inline style and script, served as before with no CSP header, and loads nothing new: `/login`'s routes, headers and the console's CSP are unchanged.
- **The app's frame**: one centred raised card (radius `xl`, the `card` shadow, at most 440 px), with the app icon's tile (written by `npm run brand` and checked by `brand:check`, like the console's favicon, which the page now has too), a title, and a line under it. Below 520 px the card's edge and shadow go, so a phone's whole screen is the card, as in the app.
- **Steps**: the title says where you are ("Welcome to SuperBot", "Two-factor authentication", "Set up two-factor authentication", "Two-factor authentication is on"), and the server's two-factor message is the line under it. The sign-in field is labelled by the existing hint ("Enter your sign-in code, or the server password."), and the code fields have accessible names.
- **Provider pills**: each provider is a full-width outlined pill in the server's order; Apple's is black in light mode and white in dark, the only colours outside the tokens with the QR code's white ground (ADR 0336). The one accent pill is the submit button. A focus ring on every control.
- **Errors with a next step**: errors sit in a soft danger notice just above the button, announced as an alert, and hidden when empty. A request that never reached the server says "Can't reach the SuperBot server. Check your connection, then try again.", and a refusal with no message says "Sign-in failed. Check your code or password, then try again." The server's own messages and the single sign-on messages are unchanged.

What the page sends is unchanged: the same element ids, the same `POST /api/auth/login` bodies (`session`, `label`, then `code` or `password`, or `challenge` with `totp` or `recoveryCode`), the same single sign-on links, and the same landing after sign-in. The provider pills stay on screen during the two-factor step, as they did.

### The setup wizard's first run

CSS outside the generated block, and a little static markup in `index.html`; `app.js` keeps its flow.

- **One card frame**: the wizard sits in a raised card with the title ("Set up this server"), a line on what the steps are for and that your place is saved, progress as a quiet pill ("2 of 6 done."), and Hide setup beside it.
- **Steps as pills**: the current step is a soft accent pill with a filled number; the others are outlined, and done steps keep their tick. A hairline sets them apart from the step's content, and another sets off Back and Next.
- **Notices**: what a step still needs (the verdict, and "Only the break-glass owner is an admin" with its link to Users) is a soft warning card; what's done a soft success card.
- **A load failure with a next step**: if `/api/setup` fails, a soft danger notice says "Can't reach the server. Check your connection, then try again." when the request never got there, or "Setup didn't load:" with the server's reason, and offers Try again, which loads the step again. It is the one script change.

Both pages follow the browser's light or dark setting.

## Alternatives considered

- **Serving the console's style sheet to `/login`**: one file, but a new public route or an exception to the admin-only rule for `/console/`, a change in what the server serves before sign-in. The generated block in the page keeps one source of tokens without it.
- **Moving the page's script to a file under a CSP**: worth doing, but it changes the page's headers and routes, which this slice keeps as they are.
- **Hiding the provider pills during the two-factor step**: tidier, and the app's two-factor screen has none, but it changes what someone can do mid sign-in. Left for a later decision.
- **Rewriting the wizard's steps as cards in `app.js`**: more layout freedom, but `app.js` builds each step's HTML, and changing it is where behaviour slips in (ADR 0337 made the same call for the rest of the console).

## Tests

- `src/__tests__/webPages.test.ts` runs the real `login.html` and the console (`index.html` with `app.js`) in jsdom against a stubbed server: the card, mark, title, labelled field and alert notice render; provider pills keep the server's order and drop bad or repeated ids; a password, a sign-in code, a challenge with a code and with a recovery code each post exactly the fields they did; setting up an authenticator shows the QR code, the grouped key and then the recovery codes under their own titles; single sign-on errors and an unreachable server show their messages; and the page's colours outside the token block are only Apple's and the QR code's. For setup: a new admin lands on it in one card with the steps, the step's notice and the way forward; Next saves the step as before; a failed load shows a notice and Try again recovers.
- `scripts/tokens.test.mjs`: the block is written to both files and sits current inside the page's `<style>`. `scripts/brand.test.mjs`: the page's favicon and mark are the brand's.
- `src/__tests__/theme.test.tsx`: text and muted text on the selected tint (the progress pill, step numbers and tags) meet 4.5:1 in both schemes; the other pairs these pages use were already checked.
- `interface_http_tests.rs`: `/login` serves the file unchanged, with its tokens inline, no style sheet link, and the same headers.

## Consequences

- Every web page a person sees before the app (sign-in, two-factor, the console's first run) follows the browser's light or dark setting; the onboarding and sign-in slice is done.
- A token change reaches `login.html` with the next `npm run tokens`, and CI fails until it does.
- The client workflow now runs on changes to `web/login.html` and `web/app.js` too.
