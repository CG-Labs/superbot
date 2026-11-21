import {
  AUTH_FACE,
  AUTH_FINGERPRINT,
  availabilityFrom,
  availabilityProblem,
  biometricLabel,
  DEFAULT_LOCK_SETTINGS,
  lockReducer,
  parseLockSettings,
  serializeLockSettings,
  stuckBeforePrompt,
  timedOut,
  UNLOCKED,
  unlockOutcome,
  type LockSettings,
  type LockState,
} from "../appLock";

const on = (lockAfter: LockSettings["lockAfter"] = 0): LockSettings => ({ enabled: true, lockAfter });
const off: LockSettings = { enabled: false, lockAfter: 0 };
const probe = (p: Partial<{ hardware: boolean; enrolled: boolean; types: number[]; level: number }> = {}) => ({
  hardware: true,
  enrolled: true,
  types: [AUTH_FACE],
  level: 3,
  ...p,
});

function run(settings: LockSettings, steps: [string, number][], start: LockState = UNLOCKED): LockState {
  return steps.reduce((s, [state, now]) => lockReducer(s, { type: "appState", state, now, settings }), start);
}

describe("lock settings (ADR 0078)", () => {
  it("is off by default and when nothing is stored", () => {
    expect(DEFAULT_LOCK_SETTINGS.enabled).toBe(false);
    expect(parseLockSettings(null)).toEqual(DEFAULT_LOCK_SETTINGS);
  });

  it("round-trips what it saves", () => {
    expect(parseLockSettings(serializeLockSettings(on(60)))).toEqual(on(60));
    expect(parseLockSettings(serializeLockSettings(off))).toEqual(off);
  });

  it("reads anything odd as off, never as a lock", () => {
    expect(parseLockSettings("not json")).toEqual(DEFAULT_LOCK_SETTINGS);
    expect(parseLockSettings('{"enabled":"yes"}').enabled).toBe(false);
    expect(parseLockSettings('{"enabled":true,"lockAfter":42}')).toEqual(on(0));
  });
});

describe("availability", () => {
  it("is unsupported on web and where there's no biometric API", () => {
    expect(availabilityFrom("web", probe())).toEqual({ kind: "unsupported" });
    expect(availabilityFrom("ios", null)).toEqual({ kind: "unsupported" });
    expect(availabilityProblem({ kind: "unsupported" })).toMatch(/browser/);
  });

  it("needs a sensor", () => {
    const a = availabilityFrom("android", probe({ hardware: false, enrolled: false, types: [] }));
    expect(a).toEqual({ kind: "no-hardware" });
    expect(availabilityProblem(a)).toMatch(/no Face ID, Touch ID or fingerprint sensor/);
  });

  it("needs biometrics set up, and says which", () => {
    const a = availabilityFrom("ios", probe({ enrolled: false, types: [AUTH_FINGERPRINT] }));
    expect(a).toEqual({ kind: "not-enrolled", label: "Touch ID" });
    expect(availabilityProblem(a)).toBe("Set up Touch ID in your device's settings first, then come back to turn on App lock.");
  });

  it("is available with enrolled biometrics", () => {
    const a = availabilityFrom("ios", probe());
    expect(a).toEqual({ kind: "available", label: "Face ID" });
    expect(availabilityProblem(a)).toBeNull();
  });

  it("names the biometrics per platform", () => {
    expect(biometricLabel("ios", [AUTH_FACE])).toBe("Face ID");
    expect(biometricLabel("android", [AUTH_FINGERPRINT])).toBe("fingerprint");
    expect(biometricLabel("android", [AUTH_FACE])).toBe("face unlock");
    expect(biometricLabel("android", [AUTH_FINGERPRINT, AUTH_FACE])).toBe("biometrics");
  });
});

describe("when it locks", () => {
  it("locks on cold start only when on", () => {
    expect(lockReducer(UNLOCKED, { type: "start", settings: on() }).locked).toBe(true);
    expect(lockReducer(UNLOCKED, { type: "start", settings: off }).locked).toBe(false);
  });

  it("'Immediately' locks on any return from the background", () => {
    const s = run(on(0), [
      ["background", 1000],
      ["active", 1001],
    ]);
    expect(s).toEqual({ locked: true, covered: false, backgroundAt: null });
  });

  it("waits out the timeout before locking again", () => {
    const quick = run(on(60), [
      ["inactive", 0],
      ["background", 0],
      ["active", 59_999],
    ]);
    expect(quick.locked).toBe(false);
    const slow = run(on(60), [
      ["background", 0],
      ["active", 60_000],
    ]);
    expect(slow.locked).toBe(true);
    expect(run(on(300), [["background", 0], ["active", 299_000]]).locked).toBe(false);
    expect(run(on(300), [["background", 0], ["active", 300_000]]).locked).toBe(true);
  });

  it("times from the first trip to the background", () => {
    const s = run(on(60), [
      ["background", 0],
      ["inactive", 30_000],
      ["background", 40_000],
      ["active", 61_000],
    ]);
    expect(s.locked).toBe(true);
  });

  it("only hides content while inactive, without counting it as leaving", () => {
    const hidden = run(on(0), [["inactive", 0]]);
    expect(hidden).toEqual({ locked: false, covered: true, backgroundAt: null });
    expect(run(on(0), [["active", 5000]], hidden)).toEqual(UNLOCKED);
  });

  it("covers content in the background for the app switcher", () => {
    expect(run(on(300), [["background", 0]]).covered).toBe(true);
  });

  it("stays locked when it was already locked", () => {
    const locked = { locked: true, covered: false, backgroundAt: null };
    expect(run(on(300), [["background", 0], ["active", 1]], locked).locked).toBe(true);
  });

  it("does nothing when off", () => {
    expect(run(off, [["inactive", 0], ["background", 0], ["active", 10_000_000]])).toEqual(UNLOCKED);
  });

  it("locks when the clock moves backwards", () => {
    expect(timedOut(on(300), 10_000, 5_000)).toBe(true);
    expect(timedOut(on(300), null, 5_000)).toBe(false);
  });

  it("clears everything on unlock", () => {
    const s = run(on(0), [["background", 0]], { locked: true, covered: false, backgroundAt: null });
    expect(lockReducer(s, { type: "unlocked" })).toEqual(UNLOCKED);
  });
});

describe("unlock failures", () => {
  it("says nothing for a cancel", () => {
    expect(unlockOutcome("user_cancel")).toEqual({ message: null, stuck: false });
    expect(unlockOutcome("system_cancel").stuck).toBe(false);
  });

  it("fails safe when the device can no longer check it's you", () => {
    for (const e of ["not_enrolled", "passcode_not_set", "not_available"]) {
      const o = unlockOutcome(e);
      expect(o.stuck).toBe(true);
      expect(o.message).toMatch(/Sign out to continue/);
    }
  });

  it("explains lockouts and mismatches", () => {
    expect(unlockOutcome("lockout").message).toMatch(/Too many tries/);
    expect(unlockOutcome("authentication_failed").message).toBe("That didn't match. Try again.");
    expect(unlockOutcome("weird").message).toBe("Couldn't unlock (weird). Try again.");
  });

  it("is stuck before prompting only with no passcode and no biometrics", () => {
    expect(stuckBeforePrompt(null)).toBe(true);
    expect(stuckBeforePrompt(probe({ hardware: false, enrolled: false, level: 0 }))).toBe(true);
    expect(stuckBeforePrompt(probe({ enrolled: false, level: 1 }))).toBe(false);
  });
});
