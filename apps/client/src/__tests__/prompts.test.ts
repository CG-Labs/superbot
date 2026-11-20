import { cleanPrompts, DEFAULT_PROMPTS, isStarter, promptsFor, starterText, validatePrompts } from "../prompts";

describe("promptsFor", () => {
  it("uses the Bot's own prompts, even none, and the defaults when it has none saved", () => {
    expect(promptsFor({ prompts: ["Check the build"] })).toEqual(["Check the build"]);
    expect(promptsFor({ prompts: [] })).toEqual([]);
    expect(promptsFor({ prompts: null })).toEqual(DEFAULT_PROMPTS);
    expect(promptsFor({})).toEqual(DEFAULT_PROMPTS);
  });
});

describe("starters", () => {
  it("are prompts that end in an ellipsis", () => {
    expect(isStarter("Set up a routine to…")).toBe(true);
    expect(isStarter("Your job is to... ")).toBe(true);
    expect(isStarter("What can you do?")).toBe(false);
    expect(isStarter("Wait… what?")).toBe(false);
  });

  it("go in the message box without the ellipsis, ready to type on", () => {
    expect(starterText("Set up a routine to…")).toBe("Set up a routine to ");
    expect(starterText("Your job is to ...")).toBe("Your job is to ");
  });
});

describe("cleanPrompts", () => {
  it("trims and drops blanks and repeats, keeping order", () => {
    expect(cleanPrompts([" b ", "", "a", "b", "   "])).toEqual(["b", "a"]);
  });
});

describe("validatePrompts", () => {
  it("matches the server's limits", () => {
    expect(validatePrompts(["a", "b"])).toBeNull();
    expect(validatePrompts(["x".repeat(201)])).toMatch(/200 characters/);
    expect(validatePrompts(["é".repeat(200)])).toBeNull();
    expect(validatePrompts(["1", "2", "3", "4", "5", "6", "7"])).toMatch(/at most 6/);
    expect(validatePrompts(["1", "2", "3", "4", "5", "6", "6", " "])).toBeNull();
  });
});
