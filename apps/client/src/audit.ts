import type { AuditEvent } from "./types";

/** What the audit log filters on, as typed. `from` and `to` are whole days, `YYYY-MM-DD`. */
export interface AuditFilters {
  action: string;
  actor: "" | "user" | "bot" | "system";
  /** A person's email or user id; wins over `actor`. */
  person: string;
  method: string;
  outcome: "" | "success" | "failure" | "denied";
  from: string;
  to: string;
}

export const NO_FILTERS: AuditFilters = { action: "", actor: "", person: "", method: "", outcome: "", from: "", to: "" };

export const ACTORS: readonly { value: AuditFilters["actor"]; label: string }[] = [
  { value: "", label: "Everyone" },
  { value: "user", label: "People" },
  { value: "bot", label: "Bots" },
  { value: "system", label: "System" },
];

/** Sign-in methods in the audit log's terms (ADR 0019). */
export const SIGN_IN: Record<string, string> = {
  password: "Password (break-glass)",
  code: "Sign-in code",
  sso: "SSO",
  none: "No auth (dev)",
  bot_token: "Bot token",
};

export const METHODS: readonly { value: string; label: string }[] = [
  { value: "", label: "Any sign-in" },
  { value: "sso", label: "SSO" },
  { value: "code", label: "Sign-in code" },
  { value: "password", label: "Password" },
  { value: "bot_token", label: "Bot token" },
  { value: "none", label: "No auth" },
];

export const OUTCOMES: readonly { value: AuditFilters["outcome"]; label: string }[] = [
  { value: "", label: "Any outcome" },
  { value: "success", label: "Success" },
  { value: "failure", label: "Failure" },
  { value: "denied", label: "Denied" },
];

/** The start of a local day, plus `addDays`, in unix ms. Null when empty. Throws on anything but a real `YYYY-MM-DD`. */
export function localDay(value: string, addDays = 0): number | null {
  const v = value.trim();
  if (!v) return null;
  const bad = new Error(`"${v}" isn't a date. Use YYYY-MM-DD.`);
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) throw bad;
  const [y, mo, d] = [Number(m[1]), Number(m[2]) - 1, Number(m[3])];
  const day = new Date(y, mo, d);
  if (day.getFullYear() !== y || day.getMonth() !== mo || day.getDate() !== d) throw bad;
  return new Date(y, mo, d + addDays).getTime();
}

/**
 * The query string `/api/audit` and its CSV export share. Days are whole days in this
 * device's time zone, sent as unix ms, as the console does. Throws on a bad date range.
 */
export function auditQuery(f: AuditFilters): string {
  const p: [string, string][] = [];
  const action = f.action.trim();
  if (action) p.push(["action", action]);
  const person = f.person.trim();
  if (person) p.push(["actor", `user:${person}`]);
  else if (f.actor) p.push(["actor", f.actor]);
  if (f.method) p.push(["method", f.method]);
  if (f.outcome) p.push(["outcome", f.outcome]);
  const from = localDay(f.from);
  const to = localDay(f.to, 1);
  if (from != null && to != null && from >= to) throw new Error("From is after To.");
  if (from != null) p.push(["from", String(from)]);
  if (to != null) p.push(["to", String(to)]);
  return p.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
}

/** The person, Bot, or part of the server that acted. */
export function actorLabel(e: AuditEvent, botName?: (id: string) => string | undefined): string {
  if (e.actorKind === "bot") return e.actorName || (e.actorId && botName?.(e.actorId)) || e.actorId || "A Bot";
  if (e.actorKind === "user") return e.actorName || e.actorEmail || e.actorId || "Unknown person";
  return `System${e.actorId ? ` · ${e.actorId}` : ""}`;
}

/** Role, how they signed in, and whom a Bot acted for, e.g. "admin · SSO · entra (work)". */
export function signInLabel(e: AuditEvent, nameOf: (userId: string) => string = (id) => id): string {
  const idp = e.idp || e.idpProvider;
  const sso = e.authMethod === "sso" && idp ? `SSO · ${idp}${e.idpProvider && e.idpProvider !== e.idp ? ` (${e.idpProvider})` : ""}` : null;
  const method = sso || (e.authMethod ? SIGN_IN[e.authMethod] ?? e.authMethod : null);
  return [e.actorRole, method, e.onBehalfOf && `for ${nameOf(e.onBehalfOf)}`].filter(Boolean).join(" · ");
}

export function targetLabel(e: AuditEvent): string {
  return [e.targetType, e.targetId].filter(Boolean).join(" ");
}

export function detailsText(e: AuditEvent): string {
  const s = JSON.stringify(e.details ?? {});
  return s === "{}" ? "" : s;
}

/** A user's name from any loaded event, for "on behalf of". */
export function nameFrom(events: AuditEvent[]): (userId: string) => string {
  return (id) => events.find((x) => x.actorKind === "user" && x.actorId === id && x.actorName)?.actorName || id;
}

/** As the server names its export: `superbot-audit-20261119-130000.csv`, in UTC. */
export function csvFileName(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  return `superbot-audit-${stamp}.csv`;
}
