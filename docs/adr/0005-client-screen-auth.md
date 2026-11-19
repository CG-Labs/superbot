# 0005: How the client shows a Bot's screen without leaking the password

Date: 2026-11-19. Status: accepted.

## Context

The Expo client (`apps/client`, ADR 0004) authenticates every API call with an HTTP Basic header built from `AUTH_PASSWORD`. A Bot's live screen is a voxl page at `/screen/<port>/`, which the proxy routes straight to voxl, not through `botd`. An iframe (web, Electron) or a WebView (iOS, Android) can't attach that header to the page's own requests or its WebSocket. Putting `user:password@host` or the password in a query string would leak it into history, logs, and referrers.

## Decision

- The client asks `GET /api/bots/:id/screen` with the Basic header. The answer is `/screen/<port>/?token=<voxl token>`.
- The live view opens with voxl's own token only. It is a random 128-bit secret per screen, made when the screen starts and dropped when it stops. `AUTH_PASSWORD` never appears in a URL, and no auth headers go to the frame.
- The client accepts only a same-origin `/screen/<digits>/` path (`resolveScreenUrl` in `src/screen.ts`) and resolves it against the server's origin. A bad or hostile response can't point the frame at another site.
- Web and Electron use an `<iframe>` with `referrerPolicy="no-referrer"`. Native uses `react-native-webview` with `incognito`, no cache, no extra windows, and navigation limited to the server's origin. `onShouldStartLoadWithRequest` does an exact-origin check, because the WebView's `originWhitelist` only matches prefixes.
- While the viewer is open the client re-asks for the link every 60 s, as the embedded `web/` app does. That keeps the screen from being reaped as idle. A new link means the screen restarted, so the viewer drops back to view-only.
- "Take over / Give back" is a transparent overlay that makes the view watch-only by default, matching `web/`. It is a UX guard, not a security boundary: whoever has the voxl link can control the screen.

## Alternatives

- **Proxy the stream through `botd` behind Basic auth.** Rejected for now. Frames can't send the header, and the WebView can only add headers to the first request, not to voxl's WebSocket.
- **Session cookies.** They belong with the M2 identity work (ROADMAP), when the client moves to token or cookie sessions.

## Consequences

- Treat the voxl link like a short-lived password for one screen. Anyone who copies it can watch and control that screen until it stops.
- The proxy must route `/screen/<port>/` to voxl (see `docs/computer.md`). Without that route, the client shows the server's error or a blank view.
- voxl decodes with WebCodecs, so the server must be on HTTPS (or localhost). Native needs iOS 16.4+ or a recent Android System WebView.
