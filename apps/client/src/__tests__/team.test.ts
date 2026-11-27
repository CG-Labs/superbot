import { ApiError, SuperBotApi } from "../api";
import {
  appliesLine,
  assignableRoles,
  blockedReason,
  canLeave,
  canRemove,
  customRoleActions,
  customRoleLine,
  leaveBlocked,
  looksLikeEmail,
  machineStatus,
  managesTeam,
  offboardingMessage,
  seatsLine,
  teamApproveBlocked,
  TEAM_LINK_EVERY_MS,
  teamLinkWanted,
  teamPays,
  teamPlanLine,
  teamRegionLine,
  teamSubscriptionLine,
  watchTeamLink,
} from "../team";
import { AppState } from "react-native";
import type { OffboardingPreview, TeamBilling, TeamMachine, TeamMember } from "../types";

const member = (id: string, role: TeamMember["role"]): TeamMember => ({ id, role, name: id, email: `${id}@example.com`, joinedAt: 1, active: true });

const machine: TeamMachine = {
  state: "running",
  tier: "small",
  region: "eu",
  enrollment: "enrolled",
  agentSeenAt: null,
  assigned: true,
  backups: true,
  lastBackupAt: null,
  createdAt: 1,
  team: true,
  releaseAt: null,
};

const preview = (p: Partial<OffboardingPreview> = {}): OffboardingPreview => ({
  user: { id: "u2", name: "Al" },
  role: "member",
  allowed: true,
  blocked: null,
  grants: 0,
  machine: { fate: "none" },
  work: { machines: null, accounts: null },
  ...p,
});

describe("team rules (mirroring the server's, ADR 0087)", () => {
  it("lets owners and admins manage, members only see", () => {
    expect([managesTeam("owner"), managesTeam("admin"), managesTeam("member"), managesTeam(undefined)]).toEqual([true, true, false, false]);
  });

  it("offers owners every role, admins none that touch owners, members none", () => {
    expect(assignableRoles("owner", member("a", "owner"))).toEqual(["owner", "admin", "member"]);
    expect(assignableRoles("admin", member("a", "member"))).toEqual(["admin", "member"]);
    expect(assignableRoles("admin", member("a", "owner"))).toEqual([]);
    expect(assignableRoles("member", member("a", "member"))).toEqual([]);
  });

  it("never offers removing yourself, and owners only to owners", () => {
    expect(canRemove("owner", member("a", "owner"), "me")).toBe(true);
    expect(canRemove("admin", member("a", "owner"), "me")).toBe(false);
    expect(canRemove("admin", member("a", "member"), "me")).toBe(true);
    expect(canRemove("owner", member("me", "owner"), "me")).toBe(false);
    expect(canRemove("member", member("a", "member"), "me")).toBe(false);
  });

  it("keeps the last owner from leaving while others are on the team", () => {
    expect(canLeave({ role: "owner", members: [member("me", "owner"), member("a", "member")] })).toBe(false);
    expect(canLeave({ role: "owner", members: [member("me", "owner"), member("a", "owner")] })).toBe(true);
    expect(canLeave({ role: "owner", members: [member("me", "owner")] })).toBe(true);
    expect(canLeave({ role: "member", members: [member("me", "member"), member("a", "owner")] })).toBe(true);
  });

  it("keeps the last person from leaving, and so deleting the team, while it pays for a plan (ADR 0093)", () => {
    const paying = { plan: { name: "pro", label: "Pro" } };
    expect(leaveBlocked({ role: "owner", members: [member("me", "owner")], billing: paying })).toMatch(/Cancel it under Manage billing/);
    expect(canLeave({ role: "owner", members: [member("me", "owner")], billing: { plan: null } })).toBe(true);
    expect(canLeave({ role: "member", members: [member("me", "member"), member("a", "owner")], billing: paying })).toBe(true);
    expect(leaveBlocked({ role: "owner", members: [member("me", "owner"), member("a", "member")] })).toMatch(/only owner/);
  });

  it("lets the last person leave a team on a plan a server admin gave it, which nobody pays for (ADR 0347)", () => {
    const given: TeamBilling = { plan: { name: "pro", label: "Pro", source: "admin" } };
    expect(canLeave({ role: "owner", members: [member("me", "owner")], billing: given })).toBe(true);
    expect(teamPays(given)).toBe(false);
    expect(teamPays({ plan: { name: "pro", label: "Pro", source: "stripe" } })).toBe(true);
    expect(teamPlanLine(given)).toBe("A server admin put everyone on the team on the Pro plan.");
  });

  it("says who pays for the team's plan and how its seats stand", () => {
    const b: TeamBilling = {
      plan: { name: "pro", label: "Pro" },
      subscription: { status: "active", tier: "pro", periodEnd: 1_797_582_000, cancelAt: null },
      seats: { members: 3, billed: 3, syncing: false, error: null },
    };
    expect(teamRegionLine({ region: "gb-lon" })).toBe("Machines and their backups stay in gb-lon, unless an admin set someone's own region.");
    expect(teamRegionLine({ region: null })).toBeNull();
    expect(teamRegionLine({})).toBeNull();
    expect(teamPlanLine(undefined)).toBeNull();
    expect(teamPlanLine({ plan: null })).toMatch(/doesn't pay/);
    expect(teamPlanLine(b)).toBe("The team pays for the Pro plan for everyone on it.");
    expect(teamSubscriptionLine(b)).toBe("Paid through Stripe · current period ends 18 Dec 2026");
    expect(teamSubscriptionLine({ ...b, subscription: { ...b.subscription!, cancelAt: 1_797_582_000 } })).toBe("Set to end 18 Dec 2026");
    expect(teamSubscriptionLine({ plan: b.plan })).toBeNull();
    expect(seatsLine(b)).toEqual({ text: expect.stringMatching(/^3 seats, one for each person/), tone: "ok" });
    expect(seatsLine({ ...b, seats: { members: 4, billed: 3, syncing: true, error: null } })).toEqual({ text: "4 people on the team, 3 billed: updating with Stripe…", tone: "dim" });
    expect(seatsLine({ ...b, seats: { members: 1, billed: 3, syncing: true, error: "Stripe refused the change." } })).toEqual({ text: "1 person on the team, 3 billed. Stripe refused the change.", tone: "warn" });
    expect(seatsLine({ plan: null, seats: null })).toBeNull();
  });

  it("puts a teammate's machine in a few words", () => {
    expect(machineStatus(null)).toEqual({ label: "No machine", detail: "", tone: "dim" });
    expect(machineStatus(machine)).toMatchObject({ label: "Running", tone: "ok", detail: "Team's machine · small · eu" });
    expect(machineStatus({ ...machine, assigned: false }).label).toBe("Running, Bots not moved yet");
    expect(machineStatus({ ...machine, enrollment: "pending" }).tone).toBe("warn");
    expect(machineStatus({ ...machine, state: "error" }).tone).toBe("bad");
    expect(machineStatus({ ...machine, state: "provisioning" }).label).toBe("Being built");
    expect(machineStatus({ ...machine, team: false, state: "suspended" })).toMatchObject({ label: "Suspended", detail: expect.stringContaining("Their own machine") });
    expect(machineStatus({ ...machine, releaseAt: Date.UTC(2030, 0, 2) }).label).toMatch(/^Released, deleted /);
    const now = Date.now();
    expect(machineStatus({ ...machine, agentSeenAt: now - 5 * 60_000 }, now).detail).toContain("seen 5 min ago");
  });

  it("says what offboarding removes, from the server's preview", () => {
    const text = offboardingMessage(
      preview({ grants: 2, machine: { fate: "suspend", days: 7 }, work: { machines: { files: "archive", graceDays: 7 }, accounts: { files: "delete", graceDays: 3 } } }),
      "Alpha",
    );
    expect(text).toContain("Al leaves Alpha");
    expect(text).toContain("lose access to teammates' shared Bots");
    expect(text).toContain("2 grants between them and teammates are revoked");
    expect(text).toContain("Their users on teammates' machines are removed, and their work there goes to the Bots' owner");
    expect(text).toContain("Their users on their accounts on this server are removed, and their work there is deleted for good after 3 days");
    expect(text).toContain("suspended now and deleted after 7 days");
    expect(text).toContain("Their own Bots, chats and secrets stay theirs");

    const gone = offboardingMessage(preview({ grants: 1, machine: { fate: "destroy", days: 0 }, work: { machines: { files: "delete", graceDays: 0 }, accounts: null } }), "Alpha");
    expect(gone).toContain("1 grant between them and teammates is revoked");
    expect(gone).toContain("deleted for good.");
    expect(gone).toContain("deleted now, with its disks");
    expect(offboardingMessage(preview({ work: { machines: null, accounts: { files: "delete", graceDays: 1 } } }), "A")).toContain("deleted for good after 1 day.");
    expect(offboardingMessage(preview({ machine: { fate: "kept" } }), "A")).toContain("Their own machine stays theirs");
    const bare = offboardingMessage(preview(), "A");
    expect(bare).not.toMatch(/grant|machine|Their users/);
  });

  it("explains a refused removal", () => {
    expect(blockedReason({ blocked: "self" })).toMatch(/Leave team/);
    expect(blockedReason({ blocked: "owner" })).toMatch(/Only the team's owners/);
    expect(blockedReason({ blocked: null })).toBeNull();
  });

  it("checks an email's shape", () => {
    expect(looksLikeEmail(" cy@example.com ")).toBe(true);
    expect(looksLikeEmail("cy")).toBe(false);
    expect(looksLikeEmail("cy@example")).toBe(false);
  });

  it("lets owners and admins give custom roles to other plain members, never over the IdP (ADR 0254)", () => {
    const choices = [{ id: "r1", name: "Team people", description: "", applies: ["users.manage"], maxDays: null }];
    const team = { role: "admin" as const, roleChoices: choices };
    const held = { id: "r1", name: "Team people" };
    expect(customRoleActions(team, member("cy", "member"), "me")).toEqual({ give: true, take: false });
    expect(customRoleActions(team, { ...member("cy", "member"), customRole: held }, "me")).toEqual({ give: true, take: true });
    expect(customRoleActions(team, { ...member("cy", "member"), customRole: { ...held, fromIdp: true } }, "me")).toEqual({ give: false, take: false });
    expect(customRoleActions(team, { ...member("cy", "member"), readOnly: true }, "me")).toEqual({ give: false, take: false });
    expect(customRoleActions(team, { ...member("ev", "admin"), customRole: held }, "me")).toEqual({ give: false, take: true });
    expect(customRoleActions(team, member("ev", "owner"), "me")).toEqual({ give: false, take: false });
    expect(customRoleActions(team, member("me", "member"), "me")).toEqual({ give: false, take: false });
    expect(customRoleActions({ role: "admin", roleChoices: [] }, member("cy", "member"), "me")).toEqual({ give: false, take: false });
    expect(customRoleActions({ role: "member", roleChoices: choices }, member("cy", "member"), "me")).toEqual({ give: false, take: false });
  });

  it("lets owners and admins approve only their plain members' requests, never over the identity provider (ADR 0263)", () => {
    const team = { members: [member("cy", "member"), member("ev", "admin"), member("ow", "owner"), { ...member("fay", "member"), customRole: { id: "r1", name: "Billing", fromIdp: true } }] };
    expect(teamApproveBlocked(team, { user: { id: "cy", name: "cy", email: null } })).toBeNull();
    expect(teamApproveBlocked(team, { user: { id: "ev", name: "ev", email: null } })).toMatch(/owners or admins/);
    expect(teamApproveBlocked(team, { user: { id: "ow", name: "ow", email: null } })).toMatch(/owners or admins/);
    expect(teamApproveBlocked(team, { user: { id: "fay", name: "fay", email: null } })).toMatch(/identity provider/);
    expect(teamApproveBlocked(team, { user: { id: "gone", name: "gone", email: null } })).toMatch(/no longer on the team/);
    expect(teamApproveBlocked(team, { user: null })).toMatch(/no longer on the team/);
  });

  it("puts a teammate's custom role in a few words", () => {
    const now = Date.UTC(2026, 10, 24);
    expect(customRoleLine(null)).toBeNull();
    expect(customRoleLine({ id: "r1", name: "Team people" }, now)).toBe("Team people");
    expect(customRoleLine({ id: "r1", name: "On call", expiresAt: now + 3 * 86_400_000 }, now)).toBe("On call · ends in 3 days");
    expect(customRoleLine({ id: "r1", name: "Billing", fromIdp: true }, now)).toBe("Billing · from your identity provider");
    expect(appliesLine({ applies: ["users.manage", "machines.manage"] })).toBe("In this team: users.manage, machines.manage. Nothing changes for them across the server.");
  });
});

describe("team API", () => {
  const api = new SuperBotApi({ baseUrl: "https://bots.example.com", token: "t" } as never);
  const fetchMock = jest.fn();
  const realFetch = globalThis.fetch;
  afterAll(() => {
    globalThis.fetch = realFetch;
  });
  beforeEach(() => {
    fetchMock.mockReset();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });
  const answer = (status: number, body: unknown) => fetchMock.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body });

  it("reads no team as null, and other failures as errors", async () => {
    answer(404, { error: "You aren't on a team." });
    expect(await api.team()).toBeNull();
    answer(500, { error: "boom" });
    await expect(api.team()).rejects.toBeInstanceOf(ApiError);
  });

  it("calls the team routes with the teammate's id escaped", async () => {
    answer(200, { allowed: true });
    await api.offboardingPreview("u 1");
    expect(fetchMock).toHaveBeenLastCalledWith("https://bots.example.com/api/team/members/u%201/offboarding", expect.objectContaining({ method: "GET" }));
    answer(200, {});
    await api.setTeamRole("u1", "admin");
    expect(fetchMock).toHaveBeenLastCalledWith(expect.stringContaining("/api/team/members/u1"), expect.objectContaining({ method: "PATCH", body: '{"role":"admin"}' }));
    answer(200, {});
    await api.giveTeamCustomRole("u 1", "r1", { expiresAt: 5 });
    expect(fetchMock).toHaveBeenLastCalledWith("https://bots.example.com/api/team/members/u%201/custom-role", expect.objectContaining({ method: "PUT", body: '{"role":"r1","expiresAt":5}' }));
    answer(200, {});
    await api.takeTeamCustomRole("u1");
    expect(fetchMock).toHaveBeenLastCalledWith("https://bots.example.com/api/team/members/u1/custom-role", expect.objectContaining({ method: "DELETE" }));
    answer(200, {});
    await api.removeTeammate("u1");
    expect(fetchMock).toHaveBeenLastCalledWith(expect.stringContaining("/api/team/members/u1"), expect.objectContaining({ method: "DELETE" }));
    answer(201, {});
    await api.inviteToTeam("cy@example.com", "member");
    expect(fetchMock).toHaveBeenLastCalledWith(expect.stringContaining("/api/team/invites"), expect.objectContaining({ method: "POST", body: '{"email":"cy@example.com","role":"member"}' }));
    answer(200, { url: "https://checkout.stripe.com/c/pay/1" });
    expect(await api.teamCheckout("pro")).toEqual({ url: "https://checkout.stripe.com/c/pay/1" });
    expect(fetchMock).toHaveBeenLastCalledWith("https://bots.example.com/api/team/billing/checkout", expect.objectContaining({ method: "POST", body: '{"tier":"pro"}' }));
    answer(200, { url: "https://billing.stripe.com/p/session/1" });
    await api.teamBillingPortal();
    expect(fetchMock).toHaveBeenLastCalledWith("https://bots.example.com/api/team/billing/portal", expect.objectContaining({ method: "POST" }));
  });

  it("shows the Team link only to people on a team or invited to one", async () => {
    const fake = (team: unknown, invites: unknown[]) => ({ team: async () => team, myTeamInvites: async () => invites }) as never;
    expect(await teamLinkWanted(fake(null, []))).toBe(false);
    expect(await teamLinkWanted(fake({ id: "t1" }, []))).toBe(true);
    expect(await teamLinkWanted(fake(null, [{ id: "i1" }]))).toBe(true);
    expect(await teamLinkWanted({ team: async () => Promise.reject(new Error("down")), myTeamInvites: async () => [] } as never)).toBe(false);
  });

  it("checks the Team link again in the foreground and on a timer, so a new invite shows up", async () => {
    jest.useFakeTimers();
    let changed: ((s: string) => void) | undefined;
    const remove = jest.fn();
    const spy = jest.spyOn(AppState, "addEventListener").mockImplementation(((_: string, fn: (s: string) => void) => {
      changed = fn;
      return { remove };
    }) as never);
    let invites: unknown[] = [];
    const api = { team: jest.fn(async () => null), myTeamInvites: jest.fn(async () => invites) } as never;
    const seen: boolean[] = [];
    const stop = watchTeamLink(api, (v) => seen.push(v));
    await jest.advanceTimersByTimeAsync(0);
    invites = [{ id: "i1" }];
    changed?.("active");
    await jest.advanceTimersByTimeAsync(0);
    invites = [];
    await jest.advanceTimersByTimeAsync(TEAM_LINK_EVERY_MS);
    expect(seen).toEqual([false, true, false]);
    stop();
    await jest.advanceTimersByTimeAsync(TEAM_LINK_EVERY_MS);
    expect(seen).toHaveLength(3);
    expect(remove).toHaveBeenCalled();
    spy.mockRestore();
    jest.useRealTimers();
  });
});
