import type { AuditEvent } from "./types";

/** What the audit log filters on, as typed. `from` and `to` are whole days, `YYYY-MM-DD`. */
export interface AuditFilters {
  action: string;
  actor: "" | "user" | "bot" | "system";
  /** A person's email or user id; wins over `actor`. */
  person: string;
  method: string;
  outcome: "" | "success" | "failure" | "denied";
  /** A Bot id: events about that Bot, whoever acted. */
  bot: string;
  /** A session id: everything one sign-in did. */
  session: string;
  /** A user id or email: what Bots and routines did for that person. */
  onBehalfOf: string;
  from: string;
  to: string;
}

export const NO_FILTERS: AuditFilters = {
  action: "",
  actor: "",
  person: "",
  method: "",
  outcome: "",
  bot: "",
  session: "",
  onBehalfOf: "",
  from: "",
  to: "",
};

/** The filters a route can open the log with, e.g. `/audit?bot=<id>`. */
export const LINK_FILTERS = ["action", "person", "bot", "session", "onBehalfOf"] as const;

export function linkedFilters(params: Partial<Record<string, string | string[]>>): Partial<AuditFilters> {
  const f: Partial<AuditFilters> = {};
  for (const k of LINK_FILTERS) {
    const v = params[k];
    const s = Array.isArray(v) ? v[0] : v;
    if (s?.trim()) f[k] = s.trim();
  }
  return f;
}

/** The approvals a person (or the timeout) settled. */
export const DECISIONS = "approval.approved,approval.denied,approval.expired";

/**
 * Kinds of action, as `action` filters: picking one fills in the Action field, so the
 * field always shows what is sent, and the server ORs a comma-separated list.
 */
export const KINDS: readonly { value: string; label: string }[] = [
  { value: "", label: "Any action" },
  { value: DECISIONS, label: "Approval decisions" },
  { value: "approval.*,policy.*,rule.*", label: "Approvals and policy" },
  { value: "auth.*,session.*", label: "Sign-ins" },
  { value: "bot.*,harness.invoked", label: "Bots and runs" },
  { value: "routine.*", label: "Routines" },
  { value: "user.*,signup.*,scim.*", label: "Users and sign-ups" },
  { value: "machine.*", label: "Machines" },
  { value: "secret.*", label: "Secrets" },
];

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
  for (const k of ["bot", "session", "onBehalfOf"] as const) {
    const v = f[k].trim();
    if (v) p.push([k, v]);
  }
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

type Names = { nameOf?: (userId: string) => string; botName?: (id: string) => string | undefined };

const withId = (name: string | undefined, id: string) => (name && name !== id ? `${name} (${id})` : id);

/** Every field an event has, labelled, in reading order. Empty fields are left out. */
export function eventFields(e: AuditEvent, { nameOf = (id) => id, botName }: Names = {}): [string, string][] {
  const idp = e.idp && e.idpProvider && e.idpProvider !== e.idp ? `${e.idp} (${e.idpProvider})` : e.idp || e.idpProvider;
  const rows: [string, string | null | undefined][] = [
    ["Time", new Date(e.at).toLocaleString()],
    ["UTC", e.time],
    ["Outcome", e.outcome],
    ["Who", `${actorLabel(e, botName)} (${e.actorKind})`],
    [e.actorKind === "bot" ? "Bot id" : e.actorKind === "user" ? "User id" : "Part", e.actorId],
    ["Email", e.actorEmail],
    ["Role", e.actorRole],
    ["Sign-in", e.authMethod ? SIGN_IN[e.authMethod] ?? e.authMethod : null],
    ["IdP", idp],
    ["IdP subject", e.actorSubject],
    ["Session", e.sessionId],
    ["On behalf of", e.onBehalfOf ? withId(nameOf(e.onBehalfOf), e.onBehalfOf) : null],
    ["About Bot", e.botId ? withId(botName?.(e.botId), e.botId) : null],
    ["Target", targetLabel(e)],
    ["IP", e.ip],
    ["User agent", e.userAgent],
    ["Event", String(e.id)],
  ];
  return rows.filter((r): r is [string, string] => !!r[1]);
}

const str = (v: unknown) => (typeof v === "string" && v ? v : null);
/** A string, or a list of strings (the server sends `covers` as one per kind of call), as one line. */
const text = (v: unknown) => (Array.isArray(v) ? str(v.filter((x) => typeof x === "string" && x).join("; ")) : str(v));

/** What an approval decision was about and how it ended (ADR 0007, 0051). Null for other events. */
export function decisionSummary(e: AuditEvent): { verdict: string; lines: [string, string][] } | null {
  const d = e.details ?? {};
  let verdict: string;
  if (e.action === "approval.approved") verdict = str(d.runId) && text(d.covers) ? "Approved for the rest of the run" : "Approved";
  else if (e.action === "approval.denied") verdict = "Denied";
  else if (e.action === "approval.expired") verdict = "Expired: nobody answered, so it was denied";
  else return null;
  const rows: [string, string | null][] = [
    ["Call", str(d.subject)],
    ["Tool", str(d.tool)],
    ["Kind", str(d.class)],
    ["Note", str(d.note)],
    ["Covers", text(d.covers)],
    ["Saved as rule", str(d.rule)],
  ];
  return { verdict, lines: rows.filter((r): r is [string, string] => !!r[1]) };
}

/** Details as indented JSON, or "" when there are none. */
export function detailsPretty(e: AuditEvent): string {
  return detailsText(e) ? JSON.stringify(e.details, null, 2) : "";
}

/** The whole event as the API sent it, for Copy or Share. */
export function eventText(e: AuditEvent): string {
  return JSON.stringify(e, null, 2);
}

/**
 * "Show everything like this" from one event. Each starts a fresh filter, so an
 * investigation that follows a session or a Bot isn't narrowed by what was set before.
 */
export function pivotsFor(e: AuditEvent, { nameOf = (id) => id, botName }: Names = {}): { label: string; filters: AuditFilters }[] {
  const out: { label: string; filters: AuditFilters }[] = [];
  const add = (label: string, f: Partial<AuditFilters>) => out.push({ label, filters: { ...NO_FILTERS, ...f } });
  add(`Only ${e.action}`, { action: e.action });
  if (e.actorKind === "user" && e.actorId) add(`Everything by ${actorLabel(e)}`, { person: e.actorId });
  const bots = [e.botId, e.actorKind === "bot" ? e.actorId : null].filter((b, i, all): b is string => !!b && all.indexOf(b) === i);
  for (const b of bots) add(`Everything about ${botName?.(b) || b}`, { bot: b });
  if (e.sessionId) add("Everything in this session", { session: e.sessionId });
  if (e.onBehalfOf) add(`Everything done for ${nameOf(e.onBehalfOf)}`, { onBehalfOf: e.onBehalfOf });
  return out;
}

/** As the server names its export: `superbot-audit-20261119-130000.csv`, in UTC. */
export function csvFileName(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  return `superbot-audit-${stamp}.csv`;
}
