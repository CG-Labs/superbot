import { classChoice, minutesLabel, newRule, parseTimeout, ruleProblem, RULE_NOTE_MAX, RULE_PATTERN_MAX, sortRules, toolLabel } from "../policy";
import type { PolicyRule } from "../types";

describe("policy helpers (ADR 0048)", () => {
  it("reads minutes from 1 to 24 hours", () => {
    expect(parseTimeout(" 15 ")).toEqual({ minutes: 15 });
    expect(parseTimeout("1440")).toEqual({ minutes: 1440 });
    for (const bad of ["", "0", "1441", "1.5", "-3", "ten"]) expect(parseTimeout(bad)).toHaveProperty("problem");
  });

  it("says minutes and hours plainly", () => {
    expect([1, 10, 60, 90, 120].map(minutesLabel)).toEqual(["1 minute", "10 minutes", "1 hour", "90 minutes", "2 hours"]);
  });

  it("checks a rule the way the server does", () => {
    expect(ruleProblem({ pattern: "git push *", tool: "shell" })).toBeNull();
    expect(ruleProblem({ pattern: "  ", tool: "*" })).toMatch(/pattern/);
    expect(ruleProblem({ pattern: "x".repeat(RULE_PATTERN_MAX + 1), tool: "*" })).toMatch(/8000/);
    expect(ruleProblem({ pattern: "x", tool: "two words" })).toMatch(/no spaces/);
    expect(ruleProblem({ pattern: "x", tool: "*", note: "n".repeat(RULE_NOTE_MAX + 1) })).toMatch(/note/);
  });

  it("builds a trimmed rule body, with the Bot only when there is one", () => {
    expect(newRule("deny", " ", " rm -rf * ", " ")).toEqual({ action: "deny", tool: "*", pattern: "rm -rf *" });
    expect(newRule("allow", "mcp__slack__post", "*", " team ", "b1")).toEqual({ botId: "b1", action: "allow", tool: "mcp__slack__post", pattern: "*", note: "team" });
  });

  it("shows a Bot's own class action or inherit", () => {
    expect(classChoice(null, "git_push")).toBe("inherit");
    expect(classChoice({ timeoutMinutes: 3 }, "git_push")).toBe("inherit");
    expect(classChoice({ classes: { git_push: "allow" } }, "git_push")).toBe("allow");
  });

  it("names tools and lists a Bot's rules before everyone's", () => {
    expect([toolLabel("*"), toolLabel("shell"), toolLabel("other"), toolLabel("Bash")]).toEqual(["Any tool", "Shell", "Other tools", "Bash"]);
    const r = (id: string, botId: string | null, at: number): PolicyRule => ({ id, botId, action: "deny", tool: "*", pattern: id, note: null, at });
    expect(sortRules([r("g2", null, 2), r("b2", "b", 4), r("g1", null, 1), r("b1", "b", 3)]).map((x) => x.id)).toEqual(["b1", "b2", "g1", "g2"]);
  });
});
