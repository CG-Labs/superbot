import { createBody, cronLabel, draftFromRoutine, patchBody, validateRoutine } from "../routines";
import type { Routine } from "../types";

const routine: Routine = {
  id: "r1",
  bot_id: "b1",
  name: "Digest",
  cron: "0 9 * * *",
  instruction: "Sum up email",
  enabled: true,
};

describe("validateRoutine", () => {
  it("accepts a complete draft", () => {
    expect(validateRoutine(draftFromRoutine(routine))).toBeNull();
  });

  it("requires a name and an instruction", () => {
    expect(validateRoutine({ ...draftFromRoutine(routine), name: "  " })).toMatch(/name/i);
    expect(validateRoutine({ ...draftFromRoutine(routine), instruction: "" })).toMatch(/should do/i);
  });

  it("requires five cron fields", () => {
    expect(validateRoutine({ ...draftFromRoutine(routine), cron: "* * *" })).toMatch(/5 fields/);
    expect(validateRoutine({ ...draftFromRoutine(routine), cron: "  0  9 * *   1-5 " })).toBeNull();
  });
});

describe("request bodies", () => {
  it("trims the create body", () => {
    expect(createBody({ name: " A ", cron: " 0 9 * * * ", instruction: " do it ", enabled: false })).toEqual({
      name: "A",
      cron: "0 9 * * *",
      instruction: "do it",
      enabled: false,
    });
  });

  it("patches only changed fields", () => {
    expect(patchBody(routine, draftFromRoutine(routine))).toEqual({});
    expect(patchBody(routine, { ...draftFromRoutine(routine), name: " Digest ", enabled: false })).toEqual({
      enabled: false,
    });
    expect(
      patchBody(routine, { name: "New", cron: "0 8 * * 1-5", instruction: "Other", enabled: true }),
    ).toEqual({ name: "New", cron: "0 8 * * 1-5", instruction: "Other" });
  });
});

describe("cronLabel", () => {
  it("names presets and falls back to the expression", () => {
    expect(cronLabel("0 9 * * 1-5")).toBe("Weekdays 9:00");
    expect(cronLabel("0  9 * * 1-5")).toBe("Weekdays 9:00");
    expect(cronLabel("*/15 * * * *")).toBe("*/15 * * * *");
  });
});
