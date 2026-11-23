import type { CustomRole, RoleBase, RoleDraft, RolesView } from "./types";

/** Names a custom role can't take, as the server refuses them (ADR 0123). */
export const RESERVED_ROLE_NAMES = ["admin", "member", "readonly", "read-only", "owner", "bot", "none"];

export const BASES: { value: RoleBase; label: string }[] = [
  { value: "member", label: "Member" },
  { value: "readonly", label: "Read-only" },
];

/** The built-in permissions every role starts from, in words. */
const BUILT_IN_LABELS: Record<string, string> = {
  account: "Their own account",
  read: "See Bots and chats",
  review: "See approvals",
  write: "Use Bots",
  approve: "Decide approvals",
  admin: "Everything (admin)",
};

export function emptyDraft(): RoleDraft {
  return { name: "", description: "", base: "member", permissions: [] };
}

export function draftOf(r: CustomRole): RoleDraft {
  return { name: r.name, description: r.description, base: r.base, permissions: [...r.permissions], maxDays: r.maxDays ?? null };
}

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
/** The longest a role can be given for, and the most a time-bound role's limit can be (ADR 0197). */
export const MAX_DAYS = 365;

/** How long a role is given for. "none": until taken away. */
export const ENDS: { value: string; label: string; ms: number | null }[] = [
  { value: "none", label: "No end", ms: null },
  { value: "8h", label: "8 hours", ms: 8 * HOUR },
  { value: "1d", label: "1 day", ms: DAY },
  { value: "7d", label: "7 days", ms: 7 * DAY },
  { value: "30d", label: "30 days", ms: 30 * DAY },
  { value: "90d", label: "90 days", ms: 90 * DAY },
];

/** The ends a role can be given with: within its limit, and never "No end" on a time-bound role. */
export function endChoices(maxDays?: number | null): { value: string; label: string }[] {
  const limit = maxDays ? maxDays * DAY : null;
  return ENDS.filter((e) => (limit == null ? true : e.ms != null && e.ms <= limit)).map(({ value, label }) => ({ value, label }));
}

/** The choice a role starts on: no end, or the shortest on a time-bound role. */
export function defaultEnd(maxDays?: number | null): string {
  return endChoices(maxDays)[0].value;
}

/** When a role given now with `choice` ends, in Unix ms, or null for none. */
export function endsAt(choice: string, now: number): number | null {
  const ms = ENDS.find((e) => e.value === choice)?.ms;
  return ms == null ? null : now + ms;
}

/** "ends in 3 days", "ends in 5 hours", "ends within the hour", or "" with no end. */
export function endsLabel(expiresAt: number | null | undefined, now: number): string {
  if (expiresAt == null) return "";
  const left = expiresAt - now;
  if (left <= 0) return "ended";
  if (left < HOUR) return "ends within the hour";
  if (left < 2 * DAY) {
    const h = Math.round(left / HOUR);
    return `ends in ${h} hour${h === 1 ? "" : "s"}`;
  }
  return `ends in ${Math.round(left / DAY)} days`;
}

export const MAX_DAYS_HINT = `A time limit is 1 to ${MAX_DAYS} days, or blank for none.`;

/** The limit typed in: null for none (blank), or undefined when it isn't 1 to 365 whole days. */
export function parseMaxDays(text: string): number | null | undefined {
  const t = text.trim();
  if (!t) return null;
  if (!/^\d+$/.test(t)) return undefined;
  const n = Number(t);
  return n >= 1 && n <= MAX_DAYS ? n : undefined;
}

/** Adds or removes a permission, kept in the server's order. */
export function togglePermission(view: Pick<RolesView, "permissions">, perms: string[], name: string): string[] {
  const on = perms.includes(name) ? perms.filter((p) => p !== name) : [...perms, name];
  return view.permissions.map((p) => p.name).filter((p) => on.includes(p));
}

/** What a role on `base` with `perms` can do, as the server would list it: its base's preset, then its own. */
export function effectivePermissions(view: Pick<RolesView, "builtIn" | "permissions">, base: RoleBase, perms: string[]): string[] {
  const preset = view.builtIn.find((b) => b.id === base)?.permissions ?? [];
  const delegable = view.permissions.map((p) => p.name).filter((p) => perms.includes(p));
  return [...preset, ...delegable.filter((p) => !preset.includes(p))];
}

/** The permissions that apply when the role is given within a team. */
export function teamPermissions(view: Pick<RolesView, "permissions">, perms: string[]): string[] {
  return view.permissions.filter((p) => p.team && perms.includes(p.name)).map((p) => p.name);
}

/** A permission in words: the server's description, or the built-in label, or its name. */
export function permissionLabel(view: Pick<RolesView, "permissions">, name: string): string {
  return view.permissions.find((p) => p.name === name)?.description ?? BUILT_IN_LABELS[name] ?? name;
}

/** Why the draft can't be saved yet, or null. Names are unique ignoring case. */
export function draftError(view: Pick<RolesView, "roles">, draft: RoleDraft, editingId?: string): string | null {
  const name = draft.name.trim();
  if (!name) return "Give the role a name.";
  if ([...name].length > 60) return "Names are at most 60 characters.";
  if (RESERVED_ROLE_NAMES.includes(name.toLowerCase())) return `"${name}" is a built-in role's name. Pick another.`;
  if (view.roles.some((r) => r.id !== editingId && r.name.toLowerCase() === name.toLowerCase())) return "A role with that name exists already.";
  if ([...draft.description.trim()].length > 500) return "Descriptions are at most 500 characters.";
  return null;
}

/** Only what changed, for `PATCH /api/roles/{id}`; null when nothing did. */
export function draftChanges(r: CustomRole, draft: RoleDraft): Partial<RoleDraft> | null {
  const out: Partial<RoleDraft> = {};
  if (draft.name.trim() !== r.name) out.name = draft.name.trim();
  if (draft.description.trim() !== r.description) out.description = draft.description.trim();
  if (draft.base !== r.base) out.base = draft.base;
  const same = draft.permissions.length === r.permissions.length && draft.permissions.every((p) => r.permissions.includes(p));
  if (!same || r.unknown.length > 0) out.permissions = draft.permissions;
  if (draft.maxDays !== undefined && draft.maxDays !== (r.maxDays ?? null)) out.maxDays = draft.maxDays;
  return Object.keys(out).length ? out : null;
}

/** What saving a new base does to the people who have the role, to confirm first; null when nothing. */
export function baseChangeWarning(r: CustomRole, draft: RoleDraft): string | null {
  if (draft.base === r.base || !r.users) return null;
  const who = r.users === 1 ? "The 1 person who has it" : `The ${r.users} people who have it`;
  const to = BASES.find((b) => b.value === draft.base)?.label ?? draft.base;
  return `${who} across the server move${r.users === 1 ? "s" : ""} to ${to} at once.${draft.base === "readonly" ? " Read-only people change nothing, so team roles they hold stop working." : ""}`;
}

/** "3 people · 1 in a team", or "Nobody has it". */
export function holdersLabel(r: Pick<CustomRole, "users" | "teamMembers">): string {
  const parts = [r.users && `${r.users} ${r.users === 1 ? "person" : "people"}`, r.teamMembers && `${r.teamMembers} in a team`].filter(Boolean);
  return parts.length ? parts.join(" · ") : "Nobody has it";
}
