import type { MyUsage, PlanUsage } from "./types";

function num(n: number | undefined): string {
  return (n ?? 0).toLocaleString("en-GB");
}

function of(used: number | undefined, limit: number | null | undefined): string {
  return limit == null ? `${num(used)} (no limit)` : `${num(used)} of ${num(limit)}`;
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
  if (t.unreportedRuns > 0) lines.push(`${runs(t.unreportedRuns)} didn't report tokens, so ${t.unreportedRuns === 1 ? "it isn't" : "they aren't"} counted.`);
  for (const b of u.byBot) lines.push(`${b.name ?? "A Bot that's gone or no longer yours"}: ${num(b.total)} tokens in ${runs(b.runs)}`);
  for (const m of u.byModel ?? []) lines.push(`${m.model ?? "Unnamed model"}: ${num(m.total)} tokens`);
  return lines;
}
