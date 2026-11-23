import type { CustomRole, ServiceAccount, ServiceAccountDraft, ServiceAccountsView, ServiceToken } from "./types";

const DAY = 24 * 60 * 60_000;

/** The built-in roles a service account can hold. Never admin (ADR 0143). */
export const BUILT_IN_ROLES = [
  { value: "readonly", label: "Read-only" },
  { value: "member", label: "Member" },
];

/** How long the old token keeps working after a rotate; the server allows at most a day. */
export const KEEP_OLD = [
  { value: 0, label: "Stop the old one now" },
  { value: 60, label: "Keep it 1 hour" },
  { value: 24 * 60, label: "Keep it 1 day" },
];

/** Expiry choices within the server's limit, with its default among them. Every token expires. */
export function expiryChoices(view: Pick<ServiceAccountsView, "defaultDays" | "maxDays">): { value: number; label: string }[] {
  const days = [...new Set([7, 30, 90, 365, view.defaultDays])].filter((d) => d >= 1 && d <= view.maxDays).sort((a, b) => a - b);
  return days.map((d) => ({ value: d, label: d === 365 ? "1 year" : d === 1 ? "1 day" : `${d} days` }));
}

export function emptyDraft(): ServiceAccountDraft {
  return { name: "", description: "", role: "readonly", team: "", owner: "" };
}

/** The role picker's value: its custom role (across the server or in its team), else its built-in role. */
export function roleKey(sa: Pick<ServiceAccount, "role" | "customRole" | "teamRole">): string {
  return sa.customRole?.id ?? sa.teamRole?.id ?? sa.role;
}

export function draftOf(sa: ServiceAccount): ServiceAccountDraft {
  return { name: sa.name, description: sa.description, role: roleKey(sa), team: sa.team?.id ?? "", owner: sa.owner?.email || sa.owner?.id || "" };
}

/**
 * Moves a draft from the account as it was (`was`) to the account as it is now (`now`): fields
 * the admin left alone take the new values, so saving never puts back another admin's change.
 */
export function rebaseDraft(draft: ServiceAccountDraft, was: ServiceAccountDraft, now: ServiceAccountDraft): ServiceAccountDraft {
  const out = { ...draft };
  for (const k of Object.keys(now) as (keyof ServiceAccountDraft)[]) if (draft[k] === was[k]) out[k] = now[k];
  return out;
}

/** "Read-only", "Help desk", "Member in Ops", or "Member + Help desk in Ops". */
export function roleLabel(sa: Pick<ServiceAccount, "role" | "customRole" | "teamRole" | "team">): string {
  const builtIn = BUILT_IN_ROLES.find((r) => r.value === sa.role)?.label ?? sa.role;
  if (!sa.team) return sa.customRole?.name ?? builtIn;
  return `${builtIn}${sa.teamRole ? ` + ${sa.teamRole.name}` : ""} in ${sa.team.name}`;
}

/** Why the draft can't be saved yet, or null. The server checks it all again. */
export function draftError(draft: ServiceAccountDraft, roles: Pick<CustomRole, "id" | "base">[]): string | null {
  const name = draft.name.trim();
  if (!name) return "Give it a name.";
  if ([...name].length > 60) return "Names are at most 60 characters.";
  if ([...draft.description.trim()].length > 500) return "Descriptions are at most 500 characters.";
  if (draft.role === "admin") return "A service account can never be an admin.";
  const custom = roles.find((r) => r.id === draft.role);
  if (!custom && !BUILT_IN_ROLES.some((r) => r.value === draft.role)) return "Pick a role.";
  if (custom && draft.team && custom.base === "readonly") return "A read-only role changes nothing in a team. Pick one based on member.";
  return null;
}

/** The body for `POST /api/service-accounts`. */
export function createBody(draft: ServiceAccountDraft): { name: string; description: string; role: string; team: string | null } {
  return { name: draft.name.trim(), description: draft.description.trim(), role: draft.role, team: draft.team || null };
}

/**
 * Only what changed, for `PATCH /api/service-accounts/{id}`; null when nothing did. A new
 * role or team sends both, so the server reads the custom role as across the server or
 * within the team it's meant for.
 */
export function draftChanges(sa: ServiceAccount, draft: ServiceAccountDraft): Partial<{ name: string; description: string; role: string; team: string | null; owner: string }> | null {
  const out: Partial<{ name: string; description: string; role: string; team: string | null; owner: string }> = {};
  const was = draftOf(sa);
  if (draft.name.trim() !== was.name) out.name = draft.name.trim();
  if (draft.description.trim() !== was.description) out.description = draft.description.trim();
  if (draft.role !== was.role || draft.team !== was.team) {
    out.role = draft.role;
    out.team = draft.team || null;
  }
  const owner = draft.owner.trim();
  if (owner && owner.toLowerCase() !== was.owner.toLowerCase()) out.owner = owner;
  return Object.keys(out).length ? out : null;
}

/** What a token on `sa` can be scoped to: what it holds, in the server's order. `account` every token has anyway. */
export function heldScopes(view: Pick<ServiceAccountsView, "scopes">, sa: Pick<ServiceAccount, "permissions" | "teamPermissions">): string[] {
  const held = new Set([...sa.permissions, ...sa.teamPermissions]);
  return view.scopes.filter((s) => s !== "account" && held.has(s));
}

/** Adds or removes a scope, kept in the server's order and to what the account holds. */
export function toggleScope(held: string[], picked: string[], name: string): string[] {
  const on = picked.includes(name) ? picked.filter((s) => s !== name) : [...picked, name];
  return held.filter((s) => on.includes(s));
}

export function scopesLabel(scopes: string[] | null): string {
  return scopes == null ? "Everything the account holds" : scopes.filter((s) => s !== "account").join(", ") || "Only who it is";
}

const when = (ms: number) => new Date(ms).toLocaleString();

/** A token's state in words, with the date that matters. */
export function tokenStatus(t: ServiceToken, now = Date.now()): string {
  if (t.state === "revoked") return `${t.revokedReason === "rotated" ? "Rotated" : "Revoked"} ${when(t.revokedAt ?? t.expiresAt)}`;
  if (t.state === "expired" || t.expiresAt <= now) return `Expired ${when(t.expiresAt)}`;
  if (t.rotatedTo) return `Replaced; works until ${when(t.expiresAt)}`;
  return `Expires ${when(t.expiresAt)}`;
}

/** Whether a live token runs out within a week, so it's worth rotating. */
export function expiresSoon(t: ServiceToken, now = Date.now()): boolean {
  return t.state === "active" && !t.rotatedTo && t.expiresAt > now && t.expiresAt - now < 7 * DAY;
}

/** Only live tokens that haven't been replaced can be rotated. */
export function canRotate(t: ServiceToken, now = Date.now()): boolean {
  return t.state === "active" && !t.rotatedTo && t.expiresAt > now;
}

export function lastUsedLabel(at: number | null | undefined, ip?: string | null): string {
  if (!at) return "Never used";
  return `Last used ${when(at)}${ip ? ` from ${ip}` : ""}`;
}
