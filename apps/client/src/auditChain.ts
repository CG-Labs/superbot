import type { AuditChainState, AuditCheckpoint, AuditExportState, AuditVerification } from "./types";

/** What the panel says about one part of the chain, and whether it's good news. */
export interface ChainLine {
  label: string;
  text: string;
  tone: "ok" | "warn" | "bad" | "dim";
}

/** The first 12 hex digits: enough to compare by eye with a copy kept elsewhere. */
export function shortHash(hash: string | null | undefined): string {
  return hash ? `${hash.slice(0, 12)}…` : "—";
}

const when = (ms: number | null | undefined) => (ms ? new Date(ms).toLocaleString() : "never");

/** A partial check's bounds, as "events 10 to 20 only"; "" for the whole log. */
export function rangeText(r: AuditVerification["range"]): string {
  if (!r || (r.from == null && r.to == null)) return "";
  if (r.from != null && r.to != null) return `events ${r.from} to ${r.to} only`;
  return r.from != null ? `from event ${r.from} only` : `up to event ${r.to} only`;
}

export function verificationLine(v: AuditVerification | null): ChainLine {
  if (!v) return { label: "Last check", text: "Not checked yet. botd checks once a day.", tone: "dim" };
  const part = rangeText(v.range);
  if (v.ok) {
    // A partial check says nothing about the rest of the log.
    if (part) return { label: "Last check", text: `Intact, ${part}: ${v.checked} events, ${when(v.at)}`, tone: "warn" };
    return { label: "Last check", text: `Intact: ${v.checked} events, ${when(v.at)}`, tone: "ok" };
  }
  const where = v.firstBroken ? ` at event ${v.firstBroken.id} (${v.firstBroken.reason})` : v.reason ? ` (${v.reason})` : "";
  return { label: "Last check", text: `Broken${where}${part ? `, ${part}` : ""}, ${when(v.at)}`, tone: "bad" };
}

export function checkpointLine(c: AuditCheckpoint | null, everyMinutes: number): ChainLine {
  const how = everyMinutes > 0 ? `every ${everyMinutes} min` : "on request only";
  if (!c) return { label: "Last checkpoint", text: `None yet (${how})`, tone: "dim" };
  return { label: "Last checkpoint", text: `Event ${c.id} signs event ${c.seq} (${shortHash(c.hash)}), ${when(c.at)}, key ${c.keyId}`, tone: "ok" };
}

export function timestampLine(s: AuditChainState): ChainLine {
  const t = s.timestamps;
  if (!t.enabled) return { label: "Timestamps", text: "Off (AUDIT_TIMESTAMP_URL)", tone: "dim" };
  const tsa = t.tsa ?? "the TSA";
  if (t.failing) return { label: "Timestamps", text: `Failing at ${tsa}: ${t.lastError ?? "no answer"}. ${t.pending} waiting.`, tone: "bad" };
  const last = t.last?.time ? `last ${when(t.last.time)} by ${t.last.tsa ?? tsa}` : "none yet";
  const trust = t.trustAnchors > 0 ? "" : " (no CA set: not checked against one)";
  return { label: "Timestamps", text: `${last}${t.pending ? `, ${t.pending} waiting` : ""}${trust}`, tone: t.trustAnchors > 0 ? "ok" : "warn" };
}

export function exportLine(x: AuditExportState): ChainLine {
  if (!x.enabled) return { label: "SIEM export", text: "Off (AUDIT_EXPORT)", tone: "dim" };
  if (x.failing) return { label: "SIEM export", text: `Failing to ${x.sink}: ${x.lastError ?? "no answer"}. ${x.pending} waiting.`, tone: "bad" };
  const a = x.archive;
  const lock = !a ? "" : a.lock === "off" ? ", objects not locked" : a.lastObject?.retainUntil ? `, last object locked (${a.lastObject.lockMode ?? a.lock}) until ${when(a.lastObject.retainUntil)}` : "";
  return { label: "SIEM export", text: `${x.sink}: ${x.pending} behind, last delivery ${when(x.deliveredAt)}${lock}`, tone: x.pending > 1000 || a?.lock === "off" ? "warn" : "ok" };
}

/** Every line, in the order the panel shows them. */
export function chainLines(s: AuditChainState): ChainLine[] {
  return [
    verificationLine(s.verification),
    { label: "Head", text: s.head ? `Event ${s.head.id} · ${shortHash(s.head.hash)}` : "No events yet", tone: "dim" },
    checkpointLine(s.checkpoints.last, s.checkpoints.everyMinutes),
    timestampLine(s),
    exportLine(s.export),
  ];
}
