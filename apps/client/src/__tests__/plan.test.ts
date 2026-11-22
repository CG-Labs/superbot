import { harnessChoices, overLimits, planUsageLines, size, storageLine, storageWarning, usageLines } from "../plan";
import type { MyUsage, PlanUsage, StorageUsage } from "../types";

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
    const capped = { ...starter, limits: { ...starter.limits, concurrentRuns: 3 } };
    expect(planUsageLines(capped).at(-1)).toBe("Tasks at once on their machine: 3");
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

describe("storage (ADR 0082)", () => {
  const storage = (used: number, limit: number | null, state: StorageUsage["state"], extra: Partial<StorageUsage> = {}): StorageUsage => ({
    used,
    limit,
    percent: limit == null ? null : Math.floor((used * 100) / limit),
    state,
    warnAt: 90,
    partial: false,
    measuredAt: 1,
    ...extra,
  });

  it("reads sizes in decimal units", () => {
    expect([0, 999, 1500, 1e6, 1_234_567, 5e9, 250e9].map(size)).toEqual(["0 bytes", "999 bytes", "1.5 KB", "1 MB", "1.2 MB", "5 GB", "250 GB"]);
  });

  it("shows storage against the plan, and nothing before it's measured", () => {
    expect(storageLine(undefined)).toBeNull();
    expect(storageLine({ ...storage(0, 1e6, null), used: null })).toBeNull();
    expect(storageLine(storage(500_000, 1e6, "ok"))).toBe("Storage: 500 KB of 1 MB (50%)");
    expect(storageLine(storage(12_000_000, null, "ok"))).toBe("Storage: 12 MB (no limit)");
    expect(storageLine(storage(500_000, 1e6, "ok", { partial: true }))).toBe("Storage: 500 KB of 1 MB (50%), at least: some folders couldn't be read");
  });

  it("warns from 90% and says how to free it when full", () => {
    expect(storageWarning(storage(500_000, 1e6, "ok"))).toBeNull();
    expect(storageWarning(storage(5e9, null, "ok"))).toBeNull();
    expect(storageWarning(storage(950_000, 1e6, "warning"))).toBe("Storage is 95% full. At 100%, Bots stop taking new tasks until files are deleted or the plan grows.");
    expect(storageWarning(storage(1_200_000, 1e6, "over"))).toMatch(/^Storage is full: new messages and tasks are refused until files are deleted/);
  });

  it("counts what the Bots' computer said, says when it hasn't, and where to delete (ADR 0105)", () => {
    const machine = (report: "fresh" | "stale" | "missing", used: number | null, measuredAt: number | null) => ({ onMachine: true, partial: report === "missing", machine: { used, report, partial: false, measuredAt } });
    expect(storageLine(storage(500_000, 1e6, "ok", machine("fresh", 400_000, 1)))).toBe("Storage: 500 KB of 1 MB (50%)");
    expect(storageLine(storage(500_000, 1e6, "ok", machine("stale", 400_000, Date.UTC(2026, 10, 2))))).toBe("Storage: 500 KB of 1 MB (50%), as the computer said on 2026-11-02");
    expect(storageLine(storage(100_000, 1e6, "ok", machine("missing", null, null)))).toBe("Storage: 100 KB of 1 MB (10%), at least: the computer hasn't said what it holds yet");
    expect(storageWarning(storage(1_200_000, 1e6, "over", machine("fresh", 1_100_000, 1)))).toBe(
      "Storage is full: new messages and tasks are refused until files are deleted on the computer Bots work on or the plan grows.",
    );
  });

  it("adds a storage line to the plan and flags it when full", () => {
    const full: PlanUsage = { ...starter, limits: { maxStorageMb: 1 }, usage: { ...starter.usage, storage: storage(1_200_000, 1e6, "over") } };
    expect(planUsageLines(full).at(-1)).toBe("Storage: 1.2 MB of 1 MB (120%)");
    expect(overLimits(full)).toContain("storage");
    const mine = { ...({} as MyUsage), period: { key: "2026-11", start: 0, end: 0, source: "calendar" as const }, tokens: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, runs: 0, unreportedRuns: 0, limit: null }, runs: { used: 0, limit: null }, byBot: [], storage: storage(500_000, 1e6, "ok") };
    expect(usageLines(mine)).toContain("Storage: 500 KB of 1 MB (50%)");
  });
});

describe("New Bot harnesses (ADR 0079)", () => {
  const names = { claude: "Claude Code", hermes: "Hermes Agent", codex: "Codex" };

  it("puts the plan's default first and says so", () => {
    expect(harnessChoices("hermes", ["claude", "hermes"], true, names)).toEqual([
      { harness: "hermes", isDefault: true, label: "Hermes Agent · your plan's default" },
      { harness: "claude", isDefault: false, label: "Claude Code" },
    ]);
  });

  it("offers the default even when it isn't installed here, so the server can say why it won't run", () => {
    expect(harnessChoices("hermes", ["claude"], true, names).map((c) => c.harness)).toEqual(["hermes", "claude"]);
  });

  it("calls an open tier's default just the default", () => {
    expect(harnessChoices("claude", ["claude", "codex"], false, names)[0].label).toBe("Claude Code · default");
  });

  it("falls back to every known harness when the server lists none", () => {
    expect(harnessChoices("pi", [], false, names).map((c) => c.harness)).toEqual(["pi", "claude", "hermes", "codex"]);
  });
});
