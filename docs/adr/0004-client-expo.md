# ADR 0004: Cross-platform client with Expo

## Status

Accepted

## Context

We need iPhone, Android, web, and desktop clients against self-hosted `botd`, without a Mac for iOS builds.

## Decision

Use **Expo (React Native + web)** in `apps/client`, with **Electron** wrapping the static web export for Windows/Linux desktop. **EAS Build** handles iOS/Android in the cloud.

Server changes: **CORS** via `CORS_ORIGINS` for browser/Electron clients; auth unchanged (HTTP Basic).

## Consequences

- Thin TypeScript UI; server remains Rust.
- iOS requires Expo account and EAS; no local `.ipa` on Linux/Windows.
- Screen streaming and full routine editor deferred in v1 client.