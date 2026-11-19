import { normalizeBaseUrl } from "./auth";
import type { Role } from "./types";

/** How long a new sign-in code works. The server allows 1 minute to 7 days. */
export const CODE_TTLS = [
  { label: "1 hour", minutes: 60 },
  { label: "24 hours", minutes: 24 * 60 },
  { label: "7 days", minutes: 7 * 24 * 60 },
] as const;

export const ROLES: { role: Role; label: string; hint: string }[] = [
  { role: "admin", label: "Admin", hint: "Everything, including users, policy, and the audit log" },
  { role: "member", label: "Member", hint: "Use and manage Bots and routines, decide approvals" },
  { role: "readonly", label: "Read-only", hint: "See everything, change nothing" },
];

const CODE_SHAPE = /^sbc_[0-9a-f]{64}$/;

/** Where people open the web client: botd's server with `/app/` (ADR 0013). */
export function appUrl(serverUrl: string): string {
  return `${normalizeBaseUrl(serverUrl)}/app/`;
}

/**
 * A link that fills in the code on the sign-in page (ADR 0021). The code rides in the
 * fragment, which browsers never send to a server or put in a Referer, so it stays out
 * of Caddy's and botd's logs. Opening it only fills the form; nothing is spent until
 * the person presses Connect, so link scanners can't use it up.
 */
export function inviteLink(serverUrl: string, code: string): string {
  return `${appUrl(serverUrl)}#code=${encodeURIComponent(code)}`;
}

export function formatExpiry(at: number, now = Date.now()): string {
  const mins = Math.round((at - now) / 60000);
  if (mins <= 0) return "expired";
  if (mins < 90) return `in ${mins} minute${mins === 1 ? "" : "s"}`;
  const hours = Math.round(mins / 60);
  if (hours < 36) return `in ${hours} hours`;
  return `in ${Math.round(hours / 24)} days`;
}

/** A ready-to-send invite: where to go, which server to enter, and the code. */
export function inviteMessage(o: { name: string; serverUrl: string; code: string; expiresAt: number; now?: number }): string {
  const server = normalizeBaseUrl(o.serverUrl);
  return [
    `Hi ${o.name}, you've been invited to SuperBot.`,
    "",
    `1. Open ${inviteLink(server, o.code)}`,
    `   (or open ${appUrl(server)} and enter the server URL ${server})`,
    `2. Sign in with this one-time code: ${o.code}`,
    "",
    `The code works once and expires ${formatExpiry(o.expiresAt, o.now)}. Don't forward it.`,
  ].join("\n");
}

/** The sign-in code in a fragment like `code=sbc_…` (with or without the `#`), if it is one. */
export function codeFromHash(hash: string | null | undefined): string | null {
  if (!hash || !hash.includes("code=")) return null;
  const raw = new URLSearchParams(hash.replace(/^#/, "")).get("code") ?? "";
  return CODE_SHAPE.test(raw) ? raw : null;
}

type Loc = { hash: string; pathname: string; search: string };
type Hist = { replaceState: (data: unknown, unused: string, url?: string) => void };

/**
 * The sign-in code from an invite link (`#code=sbc_…`), if the page was opened with one.
 * Removes it from the address bar and history either way, so it isn't left behind.
 * Expo Router also keeps the fragment as the `#` param, so the index route drops it there too.
 */
export function takeInviteCode(
  loc: Loc | undefined = typeof window === "undefined" ? undefined : window.location,
  hist: Hist | undefined = typeof window === "undefined" ? undefined : window.history,
): string | null {
  if (!loc?.hash || !loc.hash.includes("code=")) return null;
  hist?.replaceState(null, "", `${loc.pathname}${loc.search}`);
  return codeFromHash(loc.hash);
}

const METHOD_LABEL: Record<string, string> = { password: "password", code: "code", sso: "SSO" };

/** "SSO (work)", "code", …: how a sign-in happened, from its method and SSO provider. */
export function signInMethod(method: string | null | undefined, idpProvider?: string | null): string {
  if (!method) return "";
  const m = METHOD_LABEL[method] ?? method;
  return idpProvider ? `${m} (${idpProvider})` : m;
}

export function relativeTime(at: number | null | undefined, now = Date.now()): string {
  if (!at) return "Never";
  const mins = Math.round((now - at) / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} d ago`;
  return new Date(at).toLocaleDateString();
}
