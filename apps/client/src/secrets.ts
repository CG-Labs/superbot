import type { PersonalSecret } from "./types";

/** The server's limits for a personal secret (ADR 0010): the server still checks every save. */
export const MAX_NAME = 128;
export const MAX_VALUE_BYTES = 64 * 1024;

const RESERVED = ["AUTH_PASSWORD", "LICENSE_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_SECRET_KEY", "TURNSTILE_SECRET", "LINODE_TOKEN", "PATH", "HOME", "USER", "LOGNAME", "SHELL", "ENV", "BASH_ENV", "NODE_OPTIONS", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS"];
const RESERVED_PREFIXES = ["SUPERBOT_", "BOT_", "SSO_", "LD_", "DYLD_", "AGENT_BROWSER_", "VOXL_"];

/** What people type, as an environment variable name: `openai api-key` becomes `OPENAI_API_KEY`. */
export function normalizeSecretName(input: string): string {
  return input.trim().toUpperCase().replace(/[\s-]+/g, "_");
}

/** Why a name won't be accepted, or null. A hint only: the server has the final say. */
export function secretNameProblem(name: string): string | null {
  if (!name) return "Give it a name, like OPENAI_API_KEY.";
  if (name.length > MAX_NAME || !/^[A-Z_][A-Z0-9_]*$/.test(name)) {
    return "Use an environment variable name: A-Z, 0-9 and _, not starting with a digit.";
  }
  if (RESERVED.includes(name) || RESERVED_PREFIXES.some((p) => name.startsWith(p))) return `${name} is reserved by SuperBot.`;
  return null;
}

/** Why a value won't be accepted, or null. */
export function secretValueProblem(value: string): string | null {
  if (!value) return "Paste the value.";
  if (value.includes("\0")) return "The value can't contain a NUL character.";
  if (new TextEncoder().encode(value).length > MAX_VALUE_BYTES) return "The value must be 64 KB or less.";
  return null;
}

function day(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

/** When a secret was saved, and when its value was last replaced. */
export function savedLine(s: PersonalSecret): string {
  const created = s.createdAt ?? s.updatedAt;
  const saved = `Saved ${day(created)}`;
  return s.updatedAt > created && day(s.updatedAt) !== day(created) ? `${saved} · replaced ${day(s.updatedAt)}` : saved;
}
