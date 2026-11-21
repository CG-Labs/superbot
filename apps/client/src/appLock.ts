/**
 * App lock (ADR 0078): an optional Face ID / Touch ID / fingerprint lock, with the device
 * passcode as the fallback. Everything here is pure, so the timing and fail-safe rules are
 * tested without a device; `AppLock.tsx` wires it to AppState and expo-local-authentication.
 */

/** Seconds in the background before a return asks to unlock again. */
export type LockAfter = 0 | 60 | 300;

export const LOCK_AFTER_OPTIONS: readonly { value: LockAfter; label: string }[] = [
  { value: 0, label: "Immediately" },
  { value: 60, label: "After 1 minute" },
  { value: 300, label: "After 5 minutes" },
];

export interface LockSettings {
  enabled: boolean;
  lockAfter: LockAfter;
}

export const LOCK_SETTINGS_KEY = "superbot.appLock";
export const DEFAULT_LOCK_SETTINGS: LockSettings = { enabled: false, lockAfter: 0 };

/** Anything unreadable is "off": a bad value must never lock someone out. */
export function parseLockSettings(raw: string | null): LockSettings {
  if (!raw) return DEFAULT_LOCK_SETTINGS;
  try {
    const v = JSON.parse(raw) as Partial<LockSettings>;
    const lockAfter = LOCK_AFTER_OPTIONS.some((o) => o.value === v.lockAfter) ? (v.lockAfter as LockAfter) : DEFAULT_LOCK_SETTINGS.lockAfter;
    return { enabled: v.enabled === true, lockAfter };
  } catch {
    return DEFAULT_LOCK_SETTINGS;
  }
}

export function serializeLockSettings(s: LockSettings): string {
  return JSON.stringify({ enabled: s.enabled, lockAfter: s.lockAfter });
}

/**
 * While a change is being saved, either value may end up stored, so leaving the app is timed
 * by the stricter: on if either is on, and the shorter timeout of those that are on.
 */
export function stricter(a: LockSettings, b: LockSettings): LockSettings {
  if (!a.enabled) return b;
  if (!b.enabled) return a;
  return { enabled: true, lockAfter: Math.min(a.lockAfter, b.lockAfter) as LockAfter };
}

/** expo-local-authentication's `AuthenticationType` values. */
export const AUTH_FINGERPRINT = 1;
export const AUTH_FACE = 2;
export const AUTH_IRIS = 3;

/** expo-local-authentication's `SecurityLevel`: NONE means no passcode and no biometrics. */
export const LEVEL_NONE = 0;

export interface DeviceProbe {
  hardware: boolean;
  enrolled: boolean;
  types: number[];
  level: number;
}

export type Availability =
  | { kind: "available"; label: string }
  | { kind: "unsupported" }
  | { kind: "no-hardware" }
  | { kind: "not-enrolled"; label: string };

/** What the device calls its biometrics, for buttons and messages. */
export function biometricLabel(os: string, types: number[]): string {
  const face = types.includes(AUTH_FACE);
  const finger = types.includes(AUTH_FINGERPRINT);
  if (os === "ios") return face ? "Face ID" : finger ? "Touch ID" : "Face ID or Touch ID";
  if (face && !finger) return "face unlock";
  if (finger && !face) return "fingerprint";
  return "biometrics";
}

/** `probe` is null where there is no biometric API at all (web and Electron). */
export function availabilityFrom(os: string, probe: DeviceProbe | null): Availability {
  if (os === "web" || !probe) return { kind: "unsupported" };
  if (!probe.hardware) return { kind: "no-hardware" };
  const label = biometricLabel(os, probe.types);
  if (!probe.enrolled) return { kind: "not-enrolled", label };
  return { kind: "available", label };
}

/** Why App lock can't be turned on, or null when it can. */
export function availabilityProblem(a: Availability): string | null {
  switch (a.kind) {
    case "available":
      return null;
    case "unsupported":
      return "App lock needs Face ID, Touch ID or a fingerprint sensor, so it isn't available in the browser or the desktop app.";
    case "no-hardware":
      return "This device has no Face ID, Touch ID or fingerprint sensor, so App lock isn't available.";
    case "not-enrolled":
      return `Set up ${a.label} in your device's settings first, then come back to turn on App lock.`;
  }
}

export function lockAfterLabel(s: LockAfter): string {
  return LOCK_AFTER_OPTIONS.find((o) => o.value === s)?.label ?? "Immediately";
}

/**
 * `locked` shows the lock screen; `covered` hides content while the app is inactive or in
 * the background, so the app switcher's snapshot shows no chats. `backgroundAt` is when the
 * app last left the foreground.
 */
export interface LockState {
  locked: boolean;
  covered: boolean;
  backgroundAt: number | null;
}

export const UNLOCKED: LockState = { locked: false, covered: false, backgroundAt: null };

export type LockEvent =
  | { type: "start"; settings: LockSettings }
  | { type: "appState"; state: string; now: number; settings: LockSettings }
  | { type: "unlocked" };

export function lockReducer(state: LockState, event: LockEvent): LockState {
  switch (event.type) {
    case "start":
      return { locked: event.settings.enabled, covered: false, backgroundAt: null };
    case "unlocked":
      return UNLOCKED;
    case "appState": {
      const { settings, now } = event;
      if (!settings.enabled) return UNLOCKED;
      if (event.state === "background") {
        return { ...state, covered: true, backgroundAt: state.backgroundAt ?? now };
      }
      // iOS goes inactive for the app switcher, Control Center and system prompts: hide,
      // but only a real trip to the background counts toward the timeout.
      if (event.state === "inactive") return { ...state, covered: true };
      if (event.state === "active") {
        return { locked: state.locked || timedOut(settings, state.backgroundAt, now), covered: false, backgroundAt: null };
      }
      return state;
    }
  }
}

/** A clock that moved backwards counts as timed out: when in doubt, lock. */
export function timedOut(settings: LockSettings, backgroundAt: number | null, now: number): boolean {
  if (backgroundAt === null) return false;
  const away = now - backgroundAt;
  return away < 0 || away >= settings.lockAfter * 1000;
}

export interface UnlockOutcome {
  /** Shown on the lock screen; null for a plain cancel. */
  message: string | null;
  /** The device can no longer check it's you: the only way on is to sign out. */
  stuck: boolean;
}

export const STUCK_MESSAGE =
  "This device no longer has Face ID, a fingerprint or a passcode set up, so SuperBot can't check it's you. Sign out to continue; you can sign in again and turn App lock back on.";

/** Turns expo-local-authentication's error codes into what the lock screen says. */
export function unlockOutcome(error: string | undefined): UnlockOutcome {
  switch (error) {
    case "user_cancel":
    case "system_cancel":
    case "app_cancel":
    case "user_fallback":
      return { message: null, stuck: false };
    case "not_enrolled":
    case "passcode_not_set":
    case "not_available":
      return { message: STUCK_MESSAGE, stuck: true };
    case "lockout":
      return { message: "Too many tries. Unlock your device with its passcode, then try again.", stuck: false };
    case "authentication_failed":
      return { message: "That didn't match. Try again.", stuck: false };
    default:
      return { message: `Couldn't unlock${error ? ` (${error})` : ""}. Try again.`, stuck: false };
  }
}

/** Before prompting: a device with no passcode and no biometrics can never unlock. */
export function stuckBeforePrompt(probe: DeviceProbe | null): boolean {
  return !probe || probe.level === LEVEL_NONE;
}
