import type { Approval, NotifyFormat, NotifyTestResult } from "./types";

/** The server's limits (ADR 0061): the server still checks every save. */
export const MAX_RECIPIENTS = 20;
export const MAX_DELAY_SECONDS = 600;
export const MAX_THROTTLE_SECONDS = 3600;

export const FORMAT_LABELS: Record<NotifyFormat, string> = { slack: "Slack-compatible", json: "JSON (signed)" };

const EMAIL = /^[^\s@<>()",;:\\[\]]+@[^\s@<>()",;:\\[\]]+\.[^\s@<>()",;:\\[\]]+$/;

/** Addresses as typed (split by commas, spaces, or lines), or why they won't be accepted. */
export function parseRecipients(text: string): { to: string[] } | { problem: string } {
  const to: string[] = [];
  for (const a of text.split(/[\s,;]+/).filter(Boolean)) {
    if (!EMAIL.test(a)) return { problem: `"${a}" isn't an email address.` };
    if (!to.some((t) => t.toLowerCase() === a.toLowerCase())) to.push(a);
  }
  if (to.length > MAX_RECIPIENTS) return { problem: `At most ${MAX_RECIPIENTS} addresses.` };
  return { to };
}

/** Whole seconds as typed, from 0 to `max`, or why not. */
export function parseSeconds(text: string, max: number): { seconds: number } | { problem: string } {
  const t = text.trim();
  if (!/^\d+$/.test(t) || Number(t) > max) return { problem: `Use whole seconds from 0 to ${max}.` };
  return { seconds: Number(t) };
}

export function secondsLabel(s: number): string {
  if (s === 0) return "right away";
  if (s % 60 === 0) return s === 60 ? "1 minute" : `${s / 60} minutes`;
  return s === 1 ? "1 second" : `${s} seconds`;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** Why the server would refuse a webhook URL, or null: https (http only to this machine), no sign-in in it. */
export function webhookUrlProblem(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return "That isn't a URL.";
  }
  if (u.username || u.password) return "Put no user name or password in the URL.";
  if (u.protocol === "https:") return null;
  if (u.protocol === "http:" && LOOPBACK.has(u.hostname)) return null;
  return "Use an https URL.";
}

/** What a test did, in a sentence. */
export function testSummary(r: NotifyTestResult): string {
  const name = (c: string) => (c === "email" ? "Email" : c === "webhook" ? "Webhook" : c);
  if (r.ok) return `Test sent: ${r.results.map((x) => name(x.channel).toLowerCase()).join(" and ")}.`;
  return r.results
    .filter((x) => !x.ok)
    .map((x) => `${name(x.channel)} failed${x.error ? `: ${x.error}` : "."}`)
    .join(" ");
}

/** The approval a notification's link names (`/home?approval=<id>`), when it looks like one. */
export function approvalParam(v: string | string[] | undefined): string | null {
  const id = Array.isArray(v) ? v[0] : v;
  return id && /^[A-Za-z0-9_-]{1,64}$/.test(id) ? id : null;
}

/** The approvals with the linked one first, and whether it is no longer waiting. */
export function focusFirst(approvals: Approval[], id: string | null | undefined): { list: Approval[]; gone: boolean } {
  if (!id) return { list: approvals, gone: false };
  const hit = approvals.find((a) => a.id === id);
  if (!hit) return { list: approvals, gone: true };
  return { list: [hit, ...approvals.filter((a) => a !== hit)], gone: false };
}
