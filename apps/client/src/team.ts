import type { SuperBotApi } from "./api";
import { relativeTime } from "./invite";
import type { OffboardingPreview, Team, TeamMachine, TeamMember, TeamRole } from "./types";

/**
 * The team screen's rules (ADR 0088). They mirror the server's (ADR 0087) so the screen
 * only offers what it would allow; the server still decides every change.
 */

export const TEAM_ROLES: { role: TeamRole; label: string }[] = [
  { role: "owner", label: "Owner" },
  { role: "admin", label: "Admin" },
  { role: "member", label: "Member" },
];

export const TEAM_ROLE_LABEL: Record<TeamRole, string> = { owner: "Owner", admin: "Admin", member: "Member" };

/** Owners and admins manage the team; members see it. */
export function managesTeam(role: TeamRole | undefined): boolean {
  return role === "owner" || role === "admin";
}

/**
 * The roles you may give `member`: owners give any, admins never make or unmake an
 * owner, and members none. A team keeps one owner; the server refuses the last one's
 * demotion.
 */
export function assignableRoles(myRole: TeamRole | undefined, member: Pick<TeamMember, "role">): TeamRole[] {
  if (myRole === "owner") return ["owner", "admin", "member"];
  if (myRole === "admin" && member.role !== "owner") return ["admin", "member"];
  return [];
}

/** Whether to offer taking `member` off the team: not yourself (that's Leave), and owners only by owners. */
export function canRemove(myRole: TeamRole | undefined, member: Pick<TeamMember, "id" | "role">, meId: string | null | undefined): boolean {
  if (!managesTeam(myRole) || member.id === meId) return false;
  return member.role !== "owner" || myRole === "owner";
}

/** The team's owners: a team keeps at least one. */
export function ownerCount(team: Pick<Team, "members">): number {
  return team.members.filter((m) => m.role === "owner").length;
}

/** Whether you may leave: the last owner can't while others are on the team. */
export function canLeave(team: Pick<Team, "members" | "role">): boolean {
  return !(team.role === "owner" && team.members.length > 1 && ownerCount(team) === 1);
}

export type Tone = "ok" | "warn" | "bad" | "dim";

/** A teammate's machine in a few words, for its owners and admins. */
export function machineStatus(m: TeamMachine | null | undefined, now = Date.now()): { label: string; detail: string; tone: Tone } {
  if (!m) return { label: "No machine", detail: "", tone: "dim" };
  const whose = m.team ? "Team's machine" : "Their own machine";
  const detail = [whose, m.tier, m.region, m.agentSeenAt ? `seen ${relativeTime(m.agentSeenAt, now).toLowerCase()}` : ""].filter(Boolean).join(" · ");
  if (m.releaseAt) return { label: `Released, deleted ${new Date(m.releaseAt).toLocaleDateString()}`, detail, tone: "warn" };
  switch (m.state) {
    case "running":
      if (m.enrollment !== "enrolled") return { label: "Running, setting up", detail, tone: "warn" };
      return { label: m.assigned ? "Running" : "Running, Bots not moved yet", detail, tone: "ok" };
    case "suspended":
      return { label: "Suspended", detail, tone: "dim" };
    case "pending":
    case "provisioning":
      return { label: "Being built", detail, tone: "warn" };
    case "error":
      return { label: "Couldn't be built", detail, tone: "bad" };
    case "destroying":
      return { label: "Being deleted", detail, tone: "warn" };
    case "destroyed":
      return { label: "Deleted", detail, tone: "dim" };
    default:
      return { label: m.state, detail, tone: "dim" };
  }
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Why the server won't let you remove them, from the preview. */
export function blockedReason(p: Pick<OffboardingPreview, "blocked">): string | null {
  if (p.blocked === "self") return "To leave the team yourself, use Leave team.";
  if (p.blocked === "owner") return "Only the team's owners can take an owner off the team.";
  return null;
}

/** What removing them does, from the server's preview: the confirmation's body. */
export function offboardingMessage(p: OffboardingPreview, teamName: string): string {
  const name = p.user.name || "They";
  const lines = [
    `${name} leaves ${teamName}. They lose access to teammates' shared Bots, and teammates lose access to theirs. Runs between them stop.`,
  ];
  if (p.grants > 0) lines.push(`${plural(p.grants, "grant")} between them and teammates ${p.grants === 1 ? "is" : "are"} revoked.`);
  if (p.work) {
    const files =
      p.work.files === "archive"
        ? "their work there goes to the Bots' owner"
        : p.work.graceDays > 0
          ? `their work there is deleted for good after ${plural(p.work.graceDays, "day")}`
          : "their work there is deleted for good";
    lines.push(`Their user and home on teammates' machines and accounts are removed, and ${files}.`);
  }
  if (p.machine.fate === "suspend") {
    lines.push(`The machine the team gave them is suspended now and deleted after ${plural(p.machine.days ?? 0, "day")}, unless they join a team again first.`);
  } else if (p.machine.fate === "destroy") {
    lines.push("The machine the team gave them is deleted now, with its disks.");
  } else if (p.machine.fate === "kept") {
    lines.push("Their own machine stays theirs.");
  }
  lines.push("Their own Bots, chats and secrets stay theirs. Everything is in the audit log.");
  return lines.join("\n\n");
}

export function looksLikeEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim()) && s.trim().length <= 254;
}

/** Whether to show the Team link: you're on a team, or one has invited you. */
export async function teamLinkWanted(api: Pick<SuperBotApi, "team" | "myTeamInvites">): Promise<boolean> {
  try {
    const [team, invites] = await Promise.all([api.team(), api.myTeamInvites()]);
    return !!team || invites.length > 0;
  } catch {
    return false;
  }
}
