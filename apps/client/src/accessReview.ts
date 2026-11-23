import { SIGN_IN } from "./audit";
import type { AccessReview, AccessReviewPerson, AccessReviewServiceAccount, AccessReviewServiceToken } from "./types";

/** A group's heading: its SCIM tenant and team, or neither. */
export function groupLabel(g: AccessReview["groups"][number]): string {
  const parts = [g.tenant && `SCIM: ${g.tenant}`, g.team && `Team: ${g.team.name}`].filter(Boolean);
  return parts.length ? parts.join(" · ") : "No team, not from SCIM";
}

/** What a reviewer should look at twice: admins, no second factor, disabled people who still hold access. */
export function flags(p: AccessReviewPerson): string[] {
  const out: string[] = [];
  const active = p.status === "active";
  if (!active) out.push("Disabled");
  if (p.breakGlass) out.push("Owner (break-glass)");
  if (active && p.role === "admin") out.push("Admin");
  if (active && !p.mfa.enabled) out.push("No second factor");
  if (p.scim) out.push(p.scim.deleted ? `Deleted in ${p.scim.tenant}` : `SCIM: ${p.scim.tenant}`);
  if (!active && (p.apiTokens.length || p.sessions.length)) out.push("Still signed in");
  if (!active && p.machine) out.push("Still has a machine");
  return out;
}

/** "SSO · work, 2 Dec 2026" or "Never signed in". */
export function lastLoginLabel(p: AccessReviewPerson, date: (ms: number) => string = (ms) => new Date(ms).toLocaleString()): string {
  if (!p.lastLogin) return "Never signed in";
  const m = p.lastLogin.method;
  const how = m === "sso" && p.lastLogin.idpProvider ? `SSO · ${p.lastLogin.idpProvider}` : m ? (SIGN_IN[m] ?? m) : null;
  return [how, date(p.lastLogin.at)].filter(Boolean).join(", ");
}

/** Their Bots as one line: "All Bots (admin)", or each Bot with its access and any grant. */
export function botAccessLabel(p: Pick<AccessReviewPerson, "botAccess">): string {
  if (p.botAccess.all) return "All Bots (admin)";
  if (!p.botAccess.bots.length) return "No Bots";
  return p.botAccess.bots
    .map((b) => {
      const whose = b.own ? "own" : `${b.owner.name ?? b.owner.id}'s`;
      return `${b.name} (${b.access}, ${whose}${b.grant ? `, granted ${b.grant}` : ""})`;
    })
    .join("; ");
}

/** "2 API tokens, 1 browser session", or "Not signed in". */
export function signInsLabel(p: AccessReviewPerson): string {
  const n = (k: number, one: string) => (k ? `${k} ${one}${k === 1 ? "" : "s"}` : null);
  return [n(p.apiTokens.length, "API token"), n(p.sessions.length, "browser session")].filter(Boolean).join(", ") || "Not signed in";
}

export function machineLabel(p: AccessReviewPerson): string {
  const m = p.machine;
  if (!m) return "No machine";
  return `${m.state}${m.assignedAt ? ", Bots run on it" : ", not assigned"}`;
}

const SERVICE_FLAGS: Record<string, string> = {
  disabled: "Disabled",
  owner_inactive: "Owner inactive",
  unscoped_token: "Token with everything",
  unused_token: "Token unused 90 days",
};

/** The server's reasons to look at a service account twice, in words. */
export function serviceFlags(s: AccessReviewServiceAccount): string[] {
  return s.flags.map((f) => SERVICE_FLAGS[f] ?? f);
}

/** "Ada (inactive)", or "No owner" when theirs is gone. */
export function ownerLabel(s: AccessReviewServiceAccount): string {
  if (!s.owner) return "No owner";
  const who = s.owner.name || s.owner.email || s.owner.id;
  return s.ownerActive ? who : `${who} (inactive)`;
}

/** "member · Exporter", with its team when it acts in one. */
export function serviceRoleLabel(s: AccessReviewServiceAccount): string {
  const custom = s.customRole ?? s.team?.customRole;
  const role = [s.role, custom?.name].filter(Boolean).join(" · ");
  return s.team ? `${role}, in ${s.team.name}` : role;
}

/** What its tokens can use today, or "Nothing" while it or its owner can't act. */
export function effectiveLabel(s: AccessReviewServiceAccount): string {
  return s.effective.length ? s.effective.join(", ") : "Nothing";
}

/** "Nightly sbsa_…ab12: read, write; expires 1 Dec 2026; last used 2 Nov 2026". */
export function serviceTokenLabel(t: AccessReviewServiceToken, date: (ms: number) => string = (ms) => new Date(ms).toLocaleDateString()): string {
  const scopes = t.scopes ? t.scopes.join(", ") : "everything it holds";
  const used = t.lastUsedAt ? `last used ${date(t.lastUsedAt)}` : "never used";
  return `${t.name} ${t.preview}: ${scopes}; ${t.replaced ? "replaced, works until" : "expires"} ${date(t.expiresAt)}; ${used}`;
}

/** As the server names its export: `superbot-access-review-20261122-090000.csv`, in UTC. */
export function csvFileName(at: number): string {
  const stamp = new Date(at).toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  return `superbot-access-review-${stamp}.csv`;
}
