# Store screenshots

The plan for the App Store and Google Play screenshots, the drafts made from it, and how to make them again.

> **Drafts, with made-up data.** The images in [`screenshots/`](screenshots/) come from the app's web build at each store's sizes, signed in to a stand-in server with invented people, company and Bots. No real server, account or customer is shown. The web build runs the same screens as the phone apps, but some controls look different on a phone (the model pickers, for one). Replace them with captures from the native builds (below) before the first submission if they differ.

## What each store needs

| Store | Device class | Size (pixels) | Count | Folder |
|-------|--------------|---------------|-------|--------|
| App Store | 6.9" iPhone | 1320 × 2868 (also takes 1290 × 2796) | 1–10 | `screenshots/iphone-6.9/` |
| App Store | 13" iPad (required: the app supports iPad) | 2064 × 2752 (also takes 2048 × 2732) | 1–10 | `screenshots/ipad-13/` |
| Google Play | Phone | 1080 × 1920 (9:16; any side 320–3840, the long side at most twice the short one) | 2–8 | `screenshots/android-phone/` |
| Google Play | Feature graphic | 1024 × 500 | 1 | [`apps/client/assets/brand/store/feature-graphic.png`](../../apps/client/assets/brand/store/feature-graphic.png) |
| Google Play | App icon | 512 × 512 | 1 | [`apps/client/assets/brand/store/play-store-icon.png`](../../apps/client/assets/brand/store/play-store-icon.png) |

App Store Connect scales the 6.9" and 13" sets down for smaller devices. Play's 7" and 10" tablet sets are optional; the iPad captures can be reused at 1600 × 2133 or similar if the owner wants them.

## The shots

In store order. Captions are optional overlays for a later design pass; the drafts have none.

| # | File | Shows | Caption |
|---|------|-------|---------|
| 1 | `01-chat.png` | A chat with a Bot: a finished task, then a choice card asking how to reply | Hand off real work to AI teammates |
| 2 | `02-approval.png` | The approvals inbox: a Bot asks before pushing code | Approve risky steps before they happen |
| 3 | `03-bots.png` | The sidebar: several Bots, one working, one with news, an approval waiting | A team of Bots, each with its own computer |
| 4 | `04-routines.png` | A Bot's details: its scheduled routines, its computer, sharing | Schedule routines that run while you're away |
| 5 | `05-sign-in.png` | Sign-in to a server, with single sign-on | Your server, your organization's sign-in |

Worth adding from the native builds, since the web build can't show them: the Bot's live screen with **Take over**, the App lock with Face ID, and a push notification on the lock screen.

## Making the drafts again

```bash
cd apps/client
npm run build:web
npm run store:screenshots        # all shots into docs/store/screenshots/
npm run store:check              # sizes and counts
```

`scripts/store-screenshots.mjs` serves the web build beside a stand-in for the server's API, with the data in `scripts/store-fixtures.mjs`, and drives headless Chrome at each size, in dark mode, with times in UTC. It needs Node 22 or later and Chrome or Chromium (set `CHROME` to its path if it isn't found). `--only 02-approval` makes one shot; `--out <dir>` writes elsewhere. To change a shot, change the fixtures or the `SHOTS` list in the script.

## Capturing from the native builds

Use a development build (`eas build --profile development`, or `npx expo run:ios` on a Mac) on the store's device class, signed in to the same stand-in server:

```bash
cd apps/client
npm run store:screenshots -- --serve 8090   # the stand-in server, any sign-in code works
```

On the sign-in screen enter `http://localhost:8090` (iOS Simulator) or `http://10.0.2.2:8090` (Android emulator) and any code. Development builds allow plain HTTP to these addresses; store builds don't. Then:

- **iPhone 6.9":** the iPhone 16 Pro Max simulator (or newer Pro Max). `xcrun simctl io booted screenshot 01-chat.png`.
- **iPad 13":** the iPad Pro 13-inch (M4) simulator. Same command.
- **Android phone:** an emulator with a 1080 × 1920 screen. `adb exec-out screencap -p > 01-chat.png`. Taller phones (1080 × 2400) are over Play's 2:1 limit: crop them to 1080 × 2160 or less. `npm run store:check` checks only the drafts in this folder.

Set the simulators to dark mode and 9:41 (`xcrun simctl status_bar booted override --time 9:41`), and keep the shots to the same five screens so the stores' sets match.
