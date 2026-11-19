import type { Routine } from "./types";

export interface RoutineDraft {
  name: string;
  cron: string;
  instruction: string;
  enabled: boolean;
}

export const CRON_PRESETS: { label: string; cron: string }[] = [
  { label: "Every hour", cron: "0 * * * *" },
  { label: "Every day 9:00", cron: "0 9 * * *" },
  { label: "Weekdays 9:00", cron: "0 9 * * 1-5" },
  { label: "Mondays 9:00", cron: "0 9 * * 1" },
];

export const EMPTY_DRAFT: RoutineDraft = { name: "", cron: CRON_PRESETS[1].cron, instruction: "", enabled: true };

export function draftFromRoutine(r: Routine): RoutineDraft {
  return { name: r.name, cron: r.cron, instruction: r.instruction, enabled: r.enabled };
}

export function cronLabel(cron: string): string {
  const normalized = cron.trim().split(/\s+/).join(" ");
  return CRON_PRESETS.find((p) => p.cron === normalized)?.label ?? cron;
}

/** Client-side check before saving. The server validates cron ranges and is authoritative. */
export function validateRoutine(d: RoutineDraft): string | null {
  if (!d.name.trim()) return "Name is required";
  if (!d.instruction.trim()) return "Say what the Bot should do";
  if (d.cron.trim().split(/\s+/).length !== 5) return "Cron needs 5 fields: minute hour day month weekday";
  return null;
}

/** Trimmed body for POST /api/bots/:id/routines. */
export function createBody(d: RoutineDraft): RoutineDraft {
  return { name: d.name.trim(), cron: d.cron.trim(), instruction: d.instruction.trim(), enabled: d.enabled };
}

/** Only the fields that changed, for PATCH /api/routines/:id. Empty when nothing changed. */
export function patchBody(original: Routine, d: RoutineDraft): Partial<RoutineDraft> {
  const next = createBody(d);
  const patch: Partial<RoutineDraft> = {};
  if (next.name !== original.name) patch.name = next.name;
  if (next.cron !== original.cron) patch.cron = next.cron;
  if (next.instruction !== original.instruction) patch.instruction = next.instruction;
  if (next.enabled !== original.enabled) patch.enabled = next.enabled;
  return patch;
}
