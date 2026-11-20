import { overLimits, planUsageLines } from "../plan";
import type { PlanUsage } from "../types";

const starter: PlanUsage = {
  name: "starter",
  label: "Starter",
  managed: true,
  limits: { maxBots: 2, monthlyRuns: 300, dailyRoutineRuns: 24, machineType: "g6-standard-1" },
  usage: { period: "2026-11", runs: 12, bots: 3, day: "2026-11-20", routineRuns: 4 },
};

describe("plan usage", () => {
  it("shows each limit against its use", () => {
    expect(planUsageLines(starter)).toEqual([
      "Bots: 3 of 2",
      "Runs in 2026-11: 12 of 300",
      "Routine runs today (UTC): 4 of 24",
      "Machine size: g6-standard-1",
    ]);
    expect(overLimits(starter)).toEqual(["Bots"]);
  });

  it("says when there's no limit, and reads servers from before routine limits", () => {
    const open: PlanUsage = { name: "self-host", label: "Self-host", managed: false, limits: {}, usage: { period: "2026-11", runs: 5, bots: 1 } };
    expect(planUsageLines(open)).toEqual(["Bots: 1 (no limit)", "Runs in 2026-11: 5 (no limit)"]);
    expect(overLimits(open)).toEqual([]);
  });
});
