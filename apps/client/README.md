# SuperBot client

Cross-platform app for a self-hosted [SuperBot](https://github.com/CG-Labs/superbot) server (`botd`).

## Stack (why Expo)

- **One codebase** for iOS, Android, web, and a thin **Electron** shell for Windows/Linux desktop.
- **EAS Build** compiles iOS on Expo’s macOS workers — no Mac required for the developer machine.
- **HTTP Basic auth + SSE** match the existing `botd` API; native apps use `react-native-sse` with `Authorization` headers; web/Electron use a fetch-based SSE reader (browser `EventSource` cannot send auth headers).
- **Rust stays on the server**; the client is a thin TypeScript UI, consistent with the repo’s “thin web client” approach.

## Prerequisites

- Node.js 20+
- A running `botd` with `AUTH_PASSWORD` set when the server is reachable beyond localhost.
- For mobile: [Expo EAS CLI](https://docs.expo.dev/build/setup/) (`npm i -g eas-cli`) and a free Expo account.

### Server setup for remote clients

```bash
# from repo root
export AUTH_PASSWORD='your-secret'
export HOST=0.0.0.0
export PORT=3000
# Optional: allow your web/Electron origin (defaults include Expo dev ports)
# export CORS_ORIGINS='https://your-site.example'
cargo run -p botd
```

The client **always** asks for a password (it never connects without credentials).

## Development

```bash
cd apps/client
npm install
npm run web          # http://localhost:8081 (add CORS origin if needed)
```

Point the login screen at `http://127.0.0.1:3000` (or your server) and enter `AUTH_PASSWORD`.

**Single sign-on:** when the server offers it (e.g. Microsoft Entra ID, [setup](../../docs/sso/entra.md)), the login screen shows **Sign in with Microsoft**. It opens the system browser (a popup on web) and comes back on `superbot://auth` (web: `<origin><base path>/auth`, e.g. `/app/auth` for the server-hosted build), which must be in the server's `SSO_APP_REDIRECTS` (`superbot://auth` and the server-hosted `/app/auth` are by default). Expo Go uses an `exp://…/--/auth` address instead; add that while developing. The desktop app loads from `file://`, so it keeps sign-in codes and the password for now.

## Features

- **Chat** over SSE, choice cards, per-Bot model and effort.
- **Routines:** open a Bot's details (tap its name) to create, edit, pause, or delete routines. Presets cover common schedules; any 5-field cron works (server time zone). The server validates cron and shows its error inline.
- **Screen:** the **Screen** button in the chat header opens the Bot's live screen (voxl). It's a side panel on wide windows and full screen on phones. It is view-only until you press **Take over**; **Give back** returns it. Web and Electron use an iframe, native apps use a WebView. The password never goes in the link (see [ADR 0008](../../docs/adr/0008-client-screen-auth.md)).
- **Handoffs:** when a Bot runs `botctl handoff`, its sidebar row says "Needs you", a banner sits on top of its chat, and **Open screen** opens the screen with control. **Done** (in the card or the screen panel) hands it back to the Bot.
- **App lock:** **Settings** in the sidebar turns on an optional lock (off by default): Face ID, Touch ID or a fingerprint, with the device passcode as the fallback, on cold start and after **Immediately**, **1 minute** or **5 minutes** away. Content is hidden in the app switcher. The lock always offers **Sign out**, and signing out turns it off. Not available on web or desktop. Face ID needs a development build, not Expo Go ([ADR 0078](../../docs/adr/0078-client-biometric-app-lock.md)).
- **Push notifications:** **Settings** also turns on pushes for this phone (off by default) when the server has them on (`PUSH_PROVIDER=expo`): a waiting approval and a finished routine, each switchable. A push names only the Bot; tapping it opens the approval or the Bot's chat. Signing out removes the phone. Not on web or desktop. Needs a development or store build with the real EAS project id in `app.json`, not Expo Go ([ADR 0080](../../docs/adr/0080-client-push-notifications.md)).
- **Admins only** (the server refuses the rest to anyone else): **Users** (the admin portal, [ADR 0021](../../docs/adr/0021-admin-portal.md)); **Audit log**, filtered by action (with presets such as approval decisions), who, person, Bot, session, on behalf of, sign-in method, outcome, and date range; tap an event for all of it and to follow its person, Bot, or session; **Export CSV** (a download on web and desktop, the share sheet on phones) ([ADR 0060](../../docs/adr/0060-client-audit-detail-and-filters.md)); and **Admin console ↗**, the server's `/console/` in a new tab, or in the system browser on phones, where you sign in once ([ADR 0028](../../docs/adr/0028-client-admin-console-link-and-audit.md)). The console is admin-only: it adds per-user machines, server secrets, and SCIM tokens, and has no chat or Bots ([ADR 0032](../../docs/adr/0032-console-admin-only.md)).

The screen needs the server's proxy to route `/screen/<port>/` to voxl ([docs/computer.md](../../docs/computer.md)) and HTTPS (or localhost), since voxl decodes with WebCodecs.

## Web static export

```bash
npm run build:web    # output in dist/
npx serve dist
```

Servers serve the client at `/app/` ([deploy/README.md](../../deploy/README.md#web-client)). That build sets the base path from `SUPERBOT_WEB_BASE_URL` (read in `app.config.js`, so other builds are unchanged):

```bash
npm run build:web:server   # SUPERBOT_WEB_BASE_URL=/app, output in dist-app/
```

Served from the server's own origin, the login fills in that origin as the Server URL.

## Desktop (Windows / Linux / macOS)

Electron loads the static web export (no Mac-only tooling):

```bash
npm run build:web
npm run desktop      # opens Electron window
```

Pack installers (on the OS you run the command):

```bash
npm run desktop:pack # electron-builder → release/
```

## Android (no Mac)

1. `eas login`
2. Edit `app.json` → run `eas init` once to get a real `extra.eas.projectId` (replace the placeholder).
3. Build:

```bash
eas build -p android --profile preview
```

Install the APK from the Expo dashboard (internal distribution). For Play Store builds, use `--profile production`.

Local debug (device/emulator + Expo Go or dev client):

```bash
npm run android
```

## iOS (no Mac — cloud only)

Apple requires signing assets; Expo stores them for you:

```bash
eas login
eas init                    # link project, set projectId in app.json
eas credentials -p ios      # let EAS create/list certificates (first time)
eas build -p ios --profile production
```

When the build finishes, install via:

- **TestFlight** — `eas submit -p ios`, or
- **Ad hoc / internal** — download the `.ipa` from the Expo build page and install with Apple Configurator / MDM / registered device UDIDs.

You cannot produce a signed `.ipa` on Linux/Windows locally; use **EAS Build** (documented above).

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run typecheck` | TypeScript |
| `npm run lint` | ESLint |
| `npm test` | Jest (`jest-expo`) unit and component tests |
| `npm run build:web` | Static web bundle (CI) |
| `npm run build:web:server` | Web bundle for the server's `/app/` path |
| `npm run desktop` | Electron dev |
| `eas build -p android` | Cloud APK/AAB |
| `eas build -p ios` | Cloud IPA |

## Not finished yet

- **Push notifications** for new chat messages (approvals and routines are built) and Web Push
- Biometric lock for stored password
- Custom app icon/branding pass beyond template assets
- macOS native binary (Electron build on macOS is optional; Linux/Windows documented above)