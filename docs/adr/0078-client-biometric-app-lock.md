# 0078: Biometric app lock in the client

## Status

Accepted (21 Nov 2026). M3 client item "biometric optional unlock" ([#37](https://github.com/CG-Labs/superbot/issues/37), [roadmap](../ROADMAP.md)). The Expo client is the primary interface ([ADR 0027](0027-expo-primary-hermes-default.md)). Its sign-in is kept in `src/auth.ts`: the keychain / keystore on phones, `localStorage` on web.

## Context

A phone that is unlocked and handed to someone, or left on a desk, opens straight into every chat, Bot screen and approval. Banking and chat apps solve this with an optional app lock. SuperBot needs the same, without a server change, without locking anyone out when their phone's biometrics change, and without breaking the web build served at `/app/`.

## Decisions

### What it is

- An **App lock** card on a new **Settings** screen (sidebar, everyone signed in). **Off by default.**
- It uses [`expo-local-authentication`](https://docs.expo.dev/versions/v58.0.0/sdk/local-authentication/): Face ID or Touch ID on iOS, the system BiometricPrompt (fingerprint, face) on Android. The **device passcode is the fallback**: `authenticateAsync` runs with device fallback on (`LAPolicyDeviceOwnerAuthentication` on iOS, `DEVICE_CREDENTIAL` on Android), so a failed or unavailable face or finger scan can still unlock with the passcode.
- **Turning it on asks for biometrics once.** It can only be turned on when the device has a sensor and enrolled biometrics, and the successful check proves the person can open what they are about to lock. Turning it off or changing the timeout needs no prompt: the app is already open.
- iOS needs `NSFaceIDUsageDescription`. It comes from the library's config plugin in `app.json` (`faceIDPermission`), so the generated native projects get it; Android's `USE_BIOMETRIC` comes from the library.

### When it locks

- **Cold start**, once the saved session is restored: while the setting is being read a signed-in app shows only an Ink cover, so content never flashes before the lock.
- **Returning from the background** after the chosen time: **Immediately**, **After 1 minute**, or **After 5 minutes** (default Immediately). The time runs from the first move to the background; a clock that moved backwards counts as timed out.
- iOS's `inactive` state (app switcher, Control Center, a system prompt) **hides content but doesn't count as leaving**, so pulling down Control Center doesn't start a lock.
- The app's **own prompts are ignored**: Face ID moves the app to `inactive`, and Android's passcode screen is a separate activity that sends it to the background. While a prompt is open, app state changes don't lock or count.
- The lock **prompts once** each time it comes to the front. After a cancel it waits for **Unlock**, so it never loops on a prompt the user dismissed.
- Only a **signed-in** app locks: there's nothing to guard on the sign-in screen.
- The screens stay mounted under the lock, so a draft or an open screen viewer survives it. The lock and the cover are a native full-screen `Modal`, presented last, so they also sit above the screens' own modals (the approvals inbox, the phone's screen viewer, Bot details): nothing under them can be read or tapped, and screen readers skip it. The setting changes on screen only once storage has saved it, so what Settings shows is what the next launch does.

### Hiding content in the app switcher

- When the app goes `inactive` or `background` with the lock on, an opaque Ink cover replaces the content, so the iOS app switcher snapshot shows no chats.
- On Android the recent-apps thumbnail can be taken before JavaScript draws the cover, so the cover is best effort there. `FLAG_SECURE` (via `expo-screen-capture`) would hide it reliably but also blocks screenshots and screen recording of the whole app, which people use to share what a Bot did; not done for now.

### Failing safe

- The lock screen **always has Sign out**. Nobody is stuck behind a prompt they can't pass (a lockout, a broken sensor).
- If the device **can no longer check it's you** (no passcode and no biometrics: `SecurityLevel.NONE` before prompting, or `not_enrolled`, `passcode_not_set`, `not_available` from the prompt), the lock says so plainly and offers only **Sign out**. Signing out clears the session from the device, so this never opens the app without a check.
- If biometrics are **removed but a passcode is still set**, the passcode keeps unlocking, and Settings explains that biometrics need setting up again.
- **Signing out, from the lock or anywhere else, turns App lock off.** It guards a session; a device that can't unlock any more must not lock the next sign-in too. Turn it on again after signing in.
- A stored setting that can't be read or parsed counts as **off**, never as a lock.

### Storage

- One key, `superbot.appLock`, holding `{"enabled": true, "lockAfter": 60}`, stored with the client's existing helpers (`storeGet` / `storeSet` in `src/auth.ts`): the keychain (iOS) or keystore-backed SecureStore (Android). Absent means off. It's a device preference, not an account setting: nothing goes to the server, and each device decides for itself.

### Web and the desktop app

- No biometric API is used in browsers or Electron. `src/localAuth.web.ts` replaces the native adapter and never loads the native module, so the web export (`/app/` on the server, and Electron) builds and runs as before.
- On web the card says App lock isn't available in the browser or the desktop app, and the lock never engages, whatever storage holds. WebAuthn could lock a web session later; it belongs with server sessions, not here.

### Code

- `src/appLock.ts`: the pure rules (settings parsing, availability, the lock state reducer, timeouts, error messages), unit-tested without a device.
- `src/localAuth.ts` / `.web.ts`: the device adapter.
- `components/AppLock.tsx`: the provider in the root layout (inside `SuperBotProvider`, around the router), the lock screen and the cover. Tests swap the adapter and storage.
- `components/SettingsView.tsx`, `app/settings.tsx`: the Settings screen and the App lock card.

## Consequences

- People who want it get a familiar, local app lock on iOS and Android with no server change and no new account data.
- Native builds need a new binary (the library has native code). Expo Go can't show Face ID; a development build can.
- The Android app switcher may still show a thumbnail of the last screen.
- Signing out turns the lock off, so someone who signs in again must turn it back on.

## Alternatives considered

- **No passcode fallback (biometrics only).** Locks out anyone whose scan fails or whose biometrics change. The passcode is the device's own root of trust anyway.
- **Turning the lock off when biometrics disappear.** Would open the app to whoever removed them. Signing out is the safe exit.
- **Storing the setting on the server.** It's about one device's hands, not the account; a server setting would lock devices that have no biometrics.
- **Locking on every `inactive`.** Control Center and notification banners would lock the app constantly.
- **`FLAG_SECURE` on Android.** Reliable switcher hiding, but it blocks all screenshots; see above.
