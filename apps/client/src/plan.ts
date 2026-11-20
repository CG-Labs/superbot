import type { PlanUsage } from "./types";

function of(used: number | undefined, limit: number | null | undefined): string {
  return limit == null ? `${used ?? 0} (no limit)` : `${used ?? 0} of ${limit}`;
}

/** A plan's limits against what someone has used, one line each, for the admin portal (ADR 0040). */
export function planUsageLines(plan: PlanUsage): string[] {
  const { limits: l, usage: u } = plan;
  const lines = [`Bots: ${of(u.bots, l.maxBots)}`, `Runs in ${u.period}: ${of(u.runs, l.monthlyRuns)}`];
  if (u.day != null) lines.push(`Routine runs today (UTC): ${of(u.routineRuns, l.dailyRoutineRuns)}`);
  if (l.machineType) lines.push(`Machine size: ${l.machineType}`);
  return lines;
}

/** Limits the user is past, which happens after a move to a smaller plan. */
export function overLimits(plan: PlanUsage): string[] {
  const { limits: l, usage: u } = plan;
  const over: string[] = [];
  if (l.maxBots != null && u.bots > l.maxBots) over.push("Bots");
  if (l.monthlyRuns != null && u.runs > l.monthlyRuns) over.push("runs");
  if (l.dailyRoutineRuns != null && (u.routineRuns ?? 0) > l.dailyRoutineRuns) over.push("routine runs");
  return over;
}
