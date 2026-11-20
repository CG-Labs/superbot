import type { NewPolicyRule, PolicyAction, PolicyOverride, PolicyRule } from "./types";

/** The server's limits (ADR 0007, 0048): the server still checks every save. */
export const MAX_TIMEOUT_MINUTES = 24 * 60;
export const RULE_PATTERN_MAX = 8000;
export const RULE_TOOL_MAX = 200;
export const RULE_NOTE_MAX = 500;

export const ACTION_LABELS: Record<PolicyAction, string> = { allow: "Allow", ask: "Ask", deny: "Deny" };
export const ACTIONS: PolicyAction[] = ["allow", "ask", "deny"];

/** The tool a rule matches: any, a kind of tool, or an exact tool name typed in. */
export const RULE_TOOLS = [
  { value: "*", label: "Any tool" },
  { value: "shell", label: "Shell" },
  { value: "file", label: "Files" },
  { value: "web", label: "Web" },
  { value: "mcp", label: "MCP" },
] as const;

export function toolLabel(tool: string): string {
  return RULE_TOOLS.find((t) => t.value === tool)?.label ?? (tool === "other" ? "Other tools" : tool);
}

/** Minutes as typed, or why they won't be accepted. */
export function parseTimeout(text: string): { minutes: number } | { problem: string } {
  const t = text.trim();
  const n = /^\d+$/.test(t) ? Number(t) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > MAX_TIMEOUT_MINUTES) return { problem: `Use whole minutes from 1 to ${MAX_TIMEOUT_MINUTES} (24 hours).` };
  return { minutes: n };
}

export function minutesLabel(m: number): string {
  if (m % 60 === 0 && m >= 60) return m === 60 ? "1 hour" : `${m / 60} hours`;
  return m === 1 ? "1 minute" : `${m} minutes`;
}

/** Why a new rule won't be accepted, or null. */
export function ruleProblem(r: Pick<NewPolicyRule, "pattern" | "tool" | "note">): string | null {
  const pattern = r.pattern.trim();
  if (!pattern) return "Give it a pattern, like git push origin *.";
  if ([...pattern].length > RULE_PATTERN_MAX) return `The pattern must be ${RULE_PATTERN_MAX} characters or fewer.`;
  const tool = r.tool.trim() || "*";
  if (/\s/.test(tool) || [...tool].length > RULE_TOOL_MAX) return "A tool name has no spaces.";
  if ([...(r.note ?? "").trim()].length > RULE_NOTE_MAX) return `The note must be ${RULE_NOTE_MAX} characters or fewer.`;
  return null;
}

/** The body for `POST /api/policy/rules`, trimmed, with empty fields left out. */
export function newRule(action: "allow" | "deny", tool: string, pattern: string, note: string, botId?: string): NewPolicyRule {
  const n = note.trim();
  return { ...(botId ? { botId } : {}), action, tool: tool.trim() || "*", pattern: pattern.trim(), ...(n ? { note: n } : {}) };
}

/** A Bot's own action for a class, or "inherit" when it follows the global policy. */
export function classChoice(o: PolicyOverride | null | undefined, cls: string): PolicyAction | "inherit" {
  return o?.classes?.[cls] ?? "inherit";
}

/** Rules for this Bot first, then the ones for every Bot; oldest first within each. */
export function sortRules(rules: PolicyRule[]): PolicyRule[] {
  return [...rules].sort((a, b) => Number(a.botId === null) - Number(b.botId === null) || a.at - b.at);
}
