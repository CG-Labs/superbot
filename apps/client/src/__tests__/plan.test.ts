import { overLimits, planUsageLines, usageLines } from "../plan";
import type { MyUsage, PlanUsage } from "../types";

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
      "Machine size on this plan: g6-standard-1",
    ]);
    expect(overLimits(starter)).toEqual(["Bots"]);
  });

  it("says when there's no limit, and reads servers from before routine limits", () => {
    const open: PlanUsage = { name: "self-host", label: "Self-host", managed: false, limits: {}, usage: { period: "2026-11", runs: 5, bots: 1 } };
    expect(planUsageLines(open)).toEqual(["Bots: 1 (no limit)", "Runs in 2026-11: 5 (no limit)"]);
    expect(overLimits(open)).toEqual([]);
  });

  it("counts model tokens in the billing period", () => {
    const pro: PlanUsage = {
      name: "pro",
      label: "Pro",
      managed: true,
      limits: { maxBots: 10, monthlyTokens: 5_000_000 },
      usage: { period: "2026-11-14T08:00:00Z", runs: 40, bots: 2, tokens: 6_000_000, periodSource: "subscription" },
    };
    expect(planUsageLines(pro)).toEqual(["Bots: 2 of 10", "Runs this billing period: 40 (no limit)", "Model tokens this billing period: 6,000,000 of 5,000,000"]);
    expect(overLimits(pro)).toEqual(["model tokens"]);
  });
});

describe("usage this period (ADR 0050)", () => {
  const totals = { input: 1000, output: 200, cacheRead: 300, cacheWrite: 0, total: 1500, runs: 2, unreportedRuns: 1 };
  const mine: MyUsage = {
    user: "u1",
    tier: { name: "pro", label: "Pro", managed: true, limits: { monthlyTokens: 5_000_000 } },
    period: { key: "2026-11-14T08:00:00Z", start: Date.UTC(2026, 10, 14, 8), end: Date.UTC(2026, 11, 14, 8), source: "subscription" },
    tokens: { ...totals, limit: 5_000_000 },
    runs: { used: 2, limit: null },
    byBot: [
      { ...totals, bot: "b1", name: "Scout" },
      { ...totals, bot: "b2", name: null, total: 0, runs: 1 },
    ],
  };

  it("shows the period, tokens against the limit, unknown runs, and each Bot", () => {
    expect(usageLines(mine)).toEqual([
      "Billing period: 2026-11-14 to 2026-12-14 (UTC)",
      "Model tokens: 1,500 of 5,000,000",
      "Input 1,000, output 200, cache 300",
      "Runs: 2 (no limit)",
      "1 run didn't report tokens, so it isn't counted.",
      "Scout: 1,500 tokens in 2 runs",
      "A Bot that's gone or no longer yours: 0 tokens in 1 run",
    ]);
  });

  it("names models only when the server sends them, and the calendar month without a subscription", () => {
    const lines = usageLines({
      ...mine,
      period: { key: "2026-11", start: Date.UTC(2026, 10, 1), end: Date.UTC(2026, 11, 1), source: "calendar" },
      tokens: { ...totals, unreportedRuns: 0, limit: null },
      byBot: [],
      byModel: [{ ...totals, model: "claude-sonnet-4-5" }],
    });
    expect(lines).toEqual([
      "This month: 2026-11-01 to 2026-12-01 (UTC)",
      "Model tokens: 1,500 (no limit)",
      "Input 1,000, output 200, cache 300",
      "Runs: 2 (no limit)",
      "claude-sonnet-4-5: 1,500 tokens",
    ]);
  });
});
