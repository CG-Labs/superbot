import type { MyUsage, PlanUsage, StorageUsage } from "./types";

function num(n: number | undefined): string {
  return (n ?? 0).toLocaleString("en-GB");
}

function of(used: number | undefined, limit: number | null | undefined): string {
  return limit == null ? `${num(used)} (no limit)` : `${num(used)} of ${num(limit)}`;
}

/** Bytes in decimal units, as plans count storage (ADR 0082): `1.2 MB`. */
export function size(bytes: number): string {
  const units: [number, string][] = [
    [1e12, "TB"],
    [1e9, "GB"],
    [1e6, "MB"],
    [1e3, "KB"],
  ];
  for (const [n, unit] of units) {
    if (bytes >= n) {
      const tenths = Math.floor((bytes * 10) / n);
      return tenths % 10 === 0 || tenths >= 1000 ? `${Math.floor(tenths / 10)} ${unit}` : `${(tenths / 10).toFixed(1)} ${unit}`;
    }
  }
  return `${bytes} bytes`;
}

/** Storage used against the plan's cap, or null before the server measured it. */
export function storageLine(s: StorageUsage | undefined): string | null {
  if (!s || s.used == null) return null;
  const used = size(s.used);
  const line = s.limit == null ? `Storage: ${used} (no limit)` : `Storage: ${used} of ${size(s.limit)} (${s.percent ?? 0}%)`;
  if (s.machine?.report === "missing") return `${line}, at least: the computer hasn't said what it holds yet`;
  if (s.partial) return `${line}, at least: some folders couldn't be read`;
  if (s.machine?.report === "stale" && s.machine.measuredAt != null) return `${line}, as the computer said on ${day(s.machine.measuredAt)}`;
  return line;
}

/** What to say when storage is nearly full or full, or null when it's fine. */
export function storageWarning(s: StorageUsage | undefined): string | null {
  if (!s || s.used == null || s.limit == null) return null;
  const where = s.onMachine ? "on the computer Bots work on" : "from the workspace";
  if (s.state === "over") return `Storage is full: new messages and tasks are refused until files are deleted ${where} or the plan grows.`;
  if (s.state === "warning") return `Storage is ${s.percent ?? s.warnAt}% full. At 100%, Bots stop taking new tasks until files are deleted or the plan grows.`;
  return null;
}

function day(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** A plan's limits against what someone has used, one line each, for the admin portal (ADR 0040). */
export function planUsageLines(plan: PlanUsage): string[] {
  const { limits: l, usage: u } = plan;
  const period = u.periodSource === "subscription" ? "this billing period" : `in ${u.period}`;
  const lines = [`Bots: ${of(u.bots, l.maxBots)}`, `Runs ${period}: ${of(u.runs, l.monthlyRuns)}`];
  if (u.tokens != null) lines.push(`Model tokens ${period}: ${of(u.tokens, l.monthlyTokens)}`);
  if (u.day != null) lines.push(`Routine runs today (UTC): ${of(u.routineRuns, l.dailyRoutineRuns)}`);
  if (l.machineType) lines.push(`Machine size on this plan: ${l.machineType}`);
  if (l.concurrentRuns != null) lines.push(`Tasks at once on their machine: ${l.concurrentRuns}`);
  const storage = storageLine(u.storage);
  if (storage) lines.push(storage);
  return lines;
}

/** Limits the user is past, which happens after a move to a smaller plan. */
export function overLimits(plan: PlanUsage): string[] {
  const { limits: l, usage: u } = plan;
  const over: string[] = [];
  if (l.maxBots != null && u.bots > l.maxBots) over.push("Bots");
  if (l.monthlyRuns != null && u.runs > l.monthlyRuns) over.push("runs");
  if (l.monthlyTokens != null && (u.tokens ?? 0) > l.monthlyTokens) over.push("model tokens");
  if (l.dailyRoutineRuns != null && (u.routineRuns ?? 0) > l.dailyRoutineRuns) over.push("routine runs");
  if (u.storage?.state === "over") over.push("storage");
  return over;
}

function runs(n: number): string {
  return `${num(n)} ${n === 1 ? "run" : "runs"}`;
}

/** Your usage this billing period, one line each, for the Plan screen (ADR 0050). */
export function usageLines(u: MyUsage): string[] {
  const t = u.tokens;
  const what = u.period.source === "subscription" ? "Billing period" : "This month";
  const lines = [
    `${what}: ${day(u.period.start)} to ${day(u.period.end)} (UTC)`,
    `Model tokens: ${of(t.total, t.limit)}`,
    `Input ${num(t.input)}, output ${num(t.output)}, cache ${num(t.cacheRead + t.cacheWrite)}`,
    `Runs: ${of(u.runs.used, u.runs.limit)}`,
  ];
  const storage = storageLine(u.storage);
  if (storage) lines.push(storage);
  if (t.unreportedRuns > 0) lines.push(`${runs(t.unreportedRuns)} didn't report tokens, so ${t.unreportedRuns === 1 ? "it isn't" : "they aren't"} counted.`);
  for (const b of u.byBot) lines.push(`${b.name ?? "A Bot that's gone or no longer yours"}: ${num(b.total)} tokens in ${runs(b.runs)}`);
  for (const m of u.byModel ?? []) lines.push(`${m.model ?? "Unnamed model"}: ${num(m.total)} tokens`);
  return lines;
}

export interface HarnessChoice {
  harness: string;
  label: string;
  isDefault: boolean;
}

/**
 * The harnesses a new Bot can take, the default first and marked (ADR 0079). On a managed
 * plan the default is the plan's, so the user picks a plan and gets its harness.
 */
export function harnessChoices(defaultHarness: string, harnesses: string[], managed: boolean, names: Record<string, string>): HarnessChoice[] {
  const list = harnesses.length ? harnesses : Object.keys(names);
  const ordered = defaultHarness ? [defaultHarness, ...list.filter((h) => h !== defaultHarness)] : list;
  return ordered.map((h) => {
    const isDefault = h === defaultHarness;
    const name = names[h] || h;
    return { harness: h, isDefault, label: isDefault ? `${name} · ${managed ? "your plan's default" : "default"}` : name };
  });
}
