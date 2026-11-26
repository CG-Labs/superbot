import React from "react";
import { act, render, screen, userEvent, within } from "@testing-library/react-native";
import { TEAM_CONFIRM_EVERY_MS, TeamView } from "../TeamView";
import { ApiError, type SuperBotApi } from "../../src/api";
import type { MyTeamInvite, OffboardingPreview, RoleRequest, Team, TeamBilling, TeamMember } from "../../src/types";

const mockConfirm = jest.fn(async (..._a: unknown[]) => true);
jest.mock("../../src/dialogs", () => ({ confirmAsync: (...a: unknown[]) => mockConfirm(...a) }));

const machine = {
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
const ada: TeamMember = { id: "ada", name: "Ada", email: "ada@example.com", role: "owner", joinedAt: 1, active: true, machine };
const al: TeamMember = { id: "al", name: "Al", email: "al@example.com", role: "member", joinedAt: 2, active: true, machine: { ...machine, state: "suspended" } };

function teamAs(role: Team["role"], manager = role !== "member"): Team {
  const strip = (m: TeamMember) => (manager ? m : { ...m, machine: undefined });
  return {
    id: "t1",
    name: "Alpha",
    machines: true,
    createdAt: 1,
    role,
    members: [strip(ada), strip(al)],
    ...(manager ? { invites: [{ id: "ti1", teamId: "t1", email: "cy@example.com", role: "admin" as const, createdAt: 1, createdBy: "ada", expiresAt: Date.UTC(2030, 0, 2) }], machineDays: 7 } : {}),
  };
}

const preview: OffboardingPreview = {
  user: { id: "al", name: "Al" },
  role: "member",
  allowed: true,
  blocked: null,
  grants: 2,
  machine: { fate: "suspend", days: 7 },
  work: { machines: { files: "archive", graceDays: 7 }, accounts: null },
};

function fakeApi(team: Team | null, invites: MyTeamInvite[] = [], requests: RoleRequest[] = []) {
  return {
    teamRoleRequests: jest.fn(async (_status?: string) => ({ team: { id: "t1", name: "Alpha" }, requests, pending: requests.length, pendingDays: 7 })),
    approveTeamRoleRequest: jest.fn(async (..._a: unknown[]) => ({})),
    denyTeamRoleRequest: jest.fn(async (..._a: unknown[]) => ({})),
    team: jest.fn(async () => team),
    myTeamInvites: jest.fn(async () => invites),
    inviteToTeam: jest.fn(async () => ({})),
    cancelTeamInvite: jest.fn(async () => {}),
    setTeamRole: jest.fn(async () => ({})),
    offboardingPreview: jest.fn(async (): Promise<OffboardingPreview> => preview),
    removeTeammate: jest.fn(async () => {}),
    giveTeamCustomRole: jest.fn(async (..._a: unknown[]) => {}),
    takeTeamCustomRole: jest.fn(async (_id: string) => {}),
    leaveTeam: jest.fn(async () => {}),
    acceptTeamInvite: jest.fn(async () => {}),
    declineTeamInvite: jest.fn(async () => {}),
    teamCheckout: jest.fn(async (tier: string) => ({ url: `https://checkout.stripe.com/c/pay/${tier}` })),
    teamBillingPortal: jest.fn(async () => ({ url: "https://billing.stripe.com/p/session/1" })),
  };
}

async function open(team: Team | null, { meId = "ada", canWrite = true, invites = [] as MyTeamInvite[], checkout = undefined as string | undefined, requests = [] as RoleRequest[] } = {}) {
  const api = fakeApi(team, invites, requests);
  const user = userEvent.setup();
  const openPage = jest.fn(async (_url: string) => {});
  await render(<TeamView api={api as unknown as SuperBotApi} meId={meId} canWrite={canWrite} onBack={jest.fn()} checkout={checkout} open={openPage} />);
  await screen.findByRole("heading", { name: team ? "People" : "You aren't on a team" });
  return { api, user, openPage };
}

const plans = [
  { name: "starter", label: "Starter", managed: true, limits: { maxBots: 2 } },
  { name: "pro", label: "Pro", managed: true, limits: { maxBots: 10 } },
];
const paying: TeamBilling = {
  plan: { name: "pro", label: "Pro" },
  subscription: { status: "active", tier: "pro", periodEnd: 1_797_582_000, cancelAt: null },
  seats: { members: 2, billed: 2, syncing: false, error: null },
  portal: true,
  plans,
  canChange: true,
};

beforeEach(() => mockConfirm.mockClear());

describe("TeamView", () => {
  it("lets an owner buy one plan for the whole team through Stripe Checkout (ADR 0093)", async () => {
    const { api, user, openPage } = await open({ ...teamAs("owner"), billing: { plan: null, subscription: null, seats: null, portal: false, plans, canChange: true } });
    const plan = within(screen.getByTestId("team-plan"));
    expect(plan.getByText("No team plan")).toBeOnTheScreen();
    expect(plan.getByText(/A seat for each person on the team/)).toBeOnTheScreen();
    expect(plan.queryByText("Manage billing")).toBeNull();
    await user.press(plan.getByRole("link", { name: "Buy Pro for the team" }));
    expect(api.teamCheckout).toHaveBeenCalledWith("pro");
    expect(openPage).toHaveBeenCalledWith("https://checkout.stripe.com/c/pay/pro");
  });

  it("shows managers the team's plan and seats, and sends them to Stripe's portal", async () => {
    const { api, user, openPage } = await open({ ...teamAs("admin"), billing: paying }, { meId: "al" });
    const plan = within(screen.getByTestId("team-plan"));
    expect(plan.getByText("Pro plan")).toBeOnTheScreen();
    expect(plan.getByText("Paid through Stripe · current period ends 18 Dec 2026")).toBeOnTheScreen();
    expect(plan.getByText(/^2 seats, one for each person on the team/)).toBeOnTheScreen();
    expect(plan.queryByRole("link", { name: /^Buy / })).toBeNull();
    await user.press(plan.getByText("Manage billing"));
    expect(api.teamBillingPortal).toHaveBeenCalledTimes(1);
    expect(openPage).toHaveBeenCalledWith("https://billing.stripe.com/p/session/1");
  });

  it("says when Stripe hasn't caught up with the team's seats", async () => {
    await open({ ...teamAs("owner"), billing: { ...paying, seats: { members: 3, billed: 2, syncing: true, error: "Stripe couldn't change the seats just now. SuperBot keeps trying." } } });
    expect(screen.getByText(/^3 people on the team, 2 billed\. Stripe couldn't change the seats/)).toBeOnTheScreen();
  });

  it("tells members the team pays, with nothing to change", async () => {
    await open({ ...teamAs("member"), billing: { plan: { name: "pro", label: "Pro" } } }, { meId: "al" });
    const plan = within(screen.getByTestId("team-plan"));
    expect(plan.getByText("The team pays for the Pro plan for everyone on it.")).toBeOnTheScreen();
    expect(plan.getByText("Only the team's owners and admins can change the team's plan.")).toBeOnTheScreen();
    expect(plan.queryByText("Manage billing")).toBeNull();
  });

  it("offers read-only managers no buttons to change the plan", async () => {
    await open({ ...teamAs("owner"), billing: { ...paying, plan: null, canChange: false } });
    expect(screen.queryByRole("link", { name: /^Buy / })).toBeNull();
    expect(screen.queryByText("Manage billing")).toBeNull();
  });

  it("has no plan section on a server that doesn't sell plans", async () => {
    await open(teamAs("owner"));
    expect(screen.queryByTestId("team-plan")).toBeNull();
  });

  it("keeps the last person on a paying team from leaving", async () => {
    await open({ ...teamAs("owner"), members: [ada], billing: paying });
    expect(screen.queryByText("Leave team")).toBeNull();
    expect(screen.getByText(/Cancel it under Manage billing before you leave/)).toBeOnTheScreen();
  });

  it("thanks managers back from Stripe, and shows the team's plan once Stripe confirms it", async () => {
    jest.useFakeTimers();
    try {
      const unpaid = { ...teamAs("owner"), billing: { plan: null, subscription: null, seats: null, portal: false, plans, canChange: true } };
      const { api } = await open(unpaid, { checkout: "success" });
      expect(screen.getByText(/team's plan changes for everyone/)).toBeOnTheScreen();
      api.team.mockResolvedValue({ ...teamAs("owner"), billing: paying });
      await act(async () => {
        jest.advanceTimersByTime(TEAM_CONFIRM_EVERY_MS);
      });
      expect(await screen.findByText("Pro plan")).toBeOnTheScreen();
      const calls = api.team.mock.calls.length;
      await act(async () => {
        jest.advanceTimersByTime(TEAM_CONFIRM_EVERY_MS * 3);
      });
      expect(api.team.mock.calls.length).toBe(calls);
    } finally {
      jest.useRealTimers();
    }
  });

  it("shows an owner the team, roles and each teammate's machine", async () => {
    await open(teamAs("owner"));
    expect(screen.getByText("Alpha")).toBeOnTheScreen();
    expect(screen.getByText(/You're owner · 2 people/)).toBeOnTheScreen();
    const alRow = within(screen.getByLabelText("Teammate Al"));
    expect(alRow.getByRole("radio", { name: "Member", checked: true })).toBeOnTheScreen();
    expect(within(screen.getByTestId("machine-al")).getByText("Suspended")).toBeOnTheScreen();
    expect(within(screen.getByTestId("machine-ada")).getByText("Running")).toBeOnTheScreen();
    expect(within(screen.getByTestId("team-invites")).getByText(/cy@example.com · Admin/)).toBeOnTheScreen();
    expect(screen.getByText("Remove from team")).toBeOnTheScreen();
    // Not yourself: that's Leave team, which the only owner can't do yet.
    expect(screen.queryByLabelText("Remove Ada")).toBeNull();
    expect(screen.queryByText("Leave team")).toBeNull();
    expect(screen.getByText(/only owner/)).toBeOnTheScreen();
  });

  it("says where the team's data stays when it has a region (ADR 0117)", async () => {
    await open({ ...teamAs("member"), region: "de-fra-2" }, { meId: "al" });
    expect(screen.getByText(/Machines and their backups stay in de-fra-2/)).toBeOnTheScreen();
  });

  it("says nothing about regions when the team has none", async () => {
    await open(teamAs("owner"));
    expect(screen.queryByText(/backups stay in/)).toBeNull();
  });

  it("gives members a read-only view with no machines, invites or actions", async () => {
    await open(teamAs("member"), { meId: "al" });
    expect(screen.getByText("Only the team's owners and admins can change the team.")).toBeOnTheScreen();
    expect(screen.queryByTestId("machine-ada")).toBeNull();
    expect(screen.queryByText("Invite a teammate")).toBeNull();
    expect(screen.queryByText("Remove from team")).toBeNull();
    expect(screen.queryAllByRole("radio")).toHaveLength(0);
    expect(screen.getByText("Leave team")).toBeOnTheScreen();
  });

  it("gives a read-only user who is a team admin no changes either", async () => {
    await open(teamAs("admin"), { meId: "al", canWrite: false });
    expect(screen.queryByText("Invite a teammate")).toBeNull();
    expect(screen.queryByText("Remove from team")).toBeNull();
    expect(screen.queryByText("Leave team")).toBeNull();
  });

  it("gives a read-only owner no Remove, even for others", async () => {
    await open(teamAs("owner"), { canWrite: false });
    expect(screen.queryByLabelText("Remove Al")).toBeNull();
    expect(screen.queryAllByRole("radio")).toHaveLength(0);
  });

  it("doesn't offer an admin the owner's role or removal", async () => {
    await open(teamAs("admin"), { meId: "al" });
    expect(screen.queryByLabelText("Remove Ada")).toBeNull();
    const alRow = within(screen.getByLabelText("Teammate Al"));
    expect(alRow.queryByRole("radio", { name: "Owner" })).toBeNull();
    expect(alRow.getByRole("radio", { name: "Admin" })).toBeOnTheScreen();
  });

  it("invites a teammate by email with a role", async () => {
    const { api, user } = await open(teamAs("owner"));
    await user.type(screen.getByLabelText("Teammate's email"), "dee@example.com");
    await user.press(screen.getAllByRole("radio", { name: "Admin" })[0]);
    await user.press(screen.getByText("Send invite"));
    expect(api.inviteToTeam).toHaveBeenCalledWith("dee@example.com", "admin");
    expect(api.team).toHaveBeenCalledTimes(2);
  });

  it("won't send an invite without an email", async () => {
    const { api, user } = await open(teamAs("owner"));
    await user.press(screen.getByText("Send invite"));
    expect(api.inviteToTeam).not.toHaveBeenCalled();
    expect(await screen.findByText("Enter their email address.")).toBeOnTheScreen();
  });

  it("cancels an invite", async () => {
    const { api, user } = await open(teamAs("owner"));
    await user.press(screen.getByLabelText("Cancel invite for cy@example.com"));
    expect(api.cancelTeamInvite).toHaveBeenCalledWith("ti1");
  });

  it("changes a role, asking first before making an owner", async () => {
    const { api, user } = await open(teamAs("owner"));
    const alRow = within(screen.getByLabelText("Teammate Al"));
    await user.press(alRow.getByRole("radio", { name: "Admin" }));
    expect(api.setTeamRole).toHaveBeenCalledWith("al", "admin");
    expect(mockConfirm).not.toHaveBeenCalled();
    mockConfirm.mockResolvedValueOnce(false);
    await user.press(alRow.getByRole("radio", { name: "Owner" }));
    expect(mockConfirm).toHaveBeenCalledWith("Make Al an owner?", expect.any(String), "Make owner");
    expect(api.setTeamRole).toHaveBeenCalledTimes(1);
  });

  describe("custom roles in the team (ADR 0254)", () => {
    const roleChoices = [
      { id: "r-ops", name: "On call", description: "Restarts machines", applies: ["machines.manage"], maxDays: 7 },
      { id: "r-people", name: "Team people", description: "", applies: ["users.manage"], maxDays: null },
    ];

    it("gives a plain member a role, for as long as its limit allows", async () => {
      const { api, user } = await open({ ...teamAs("owner"), roleChoices });
      expect(screen.queryByLabelText("Give team role for Ada")).toBeNull();
      await user.press(screen.getByLabelText("Give team role for Al"));
      const panel = within(screen.getByTestId("give-role"));
      expect(panel.getByText("Restarts machines")).toBeOnTheScreen();
      expect(panel.getByText(/In this team: machines.manage/)).toBeOnTheScreen();
      expect(panel.queryByRole("radio", { name: "No end" })).toBeNull();
      expect(panel.queryByRole("radio", { name: "30 days" })).toBeNull();
      await user.press(panel.getByRole("radio", { name: "Team people" }));
      expect(panel.getByRole("radio", { name: "No end", checked: true })).toBeOnTheScreen();
      await user.press(panel.getByRole("radio", { name: "7 days" }));
      const before = Date.now();
      await user.press(panel.getByText("Give Team people"));
      expect(api.giveTeamCustomRole).toHaveBeenCalledWith("al", "r-people", { expiresAt: expect.any(Number) });
      const [, , opts] = api.giveTeamCustomRole.mock.calls[0] as unknown as [string, string, { expiresAt: number }];
      expect(opts.expiresAt - before).toBeGreaterThanOrEqual(7 * 86_400_000);
      expect(screen.queryByTestId("give-role")).toBeNull();
    });

    it("shows a teammate's role and takes it away after asking", async () => {
      const team = { ...teamAs("admin"), roleChoices, members: [ada, { ...al, customRole: { id: "r-people", name: "Team people" } }] };
      const { api, user } = await open(team, { meId: "ada" });
      expect(screen.getByTestId("custom-role-al")).toHaveTextContent("Team role: Team people");
      await user.press(screen.getByLabelText("Change team role for Al"));
      const panel = within(screen.getByTestId("give-role"));
      expect(panel.getByRole("radio", { name: "Team people", checked: true })).toBeOnTheScreen();
      expect(panel.getByRole("radio", { name: "No end", checked: true })).toBeOnTheScreen();
      await user.press(panel.getByText("Cancel"));
      await user.press(screen.getByLabelText("Take away team role from Al"));
      expect(mockConfirm).toHaveBeenCalledWith("Take Team people away from Al?", expect.any(String), "Take away");
      expect(api.takeTeamCustomRole).toHaveBeenCalledWith("al");
    });

    it("starts a change of a time-bound role near the end it has now", async () => {
      const held = { id: "r-ops", name: "On call", expiresAt: Date.now() + 5 * 86_400_000 };
      const { user } = await open({ ...teamAs("owner"), roleChoices, members: [ada, { ...al, customRole: held }] });
      await user.press(screen.getByLabelText("Change team role for Al"));
      const panel = within(screen.getByTestId("give-role"));
      expect(panel.getByRole("radio", { name: "On call", checked: true })).toBeOnTheScreen();
      expect(panel.getByRole("radio", { name: "7 days", checked: true })).toBeOnTheScreen();
    });

    const fromIdp = { ...al, customRole: { id: "r-b", name: "Billing", fromIdp: true } };

    it("leaves a role from the identity provider alone", async () => {
      await open({ ...teamAs("owner"), roleChoices, members: [ada, fromIdp] });
      expect(screen.getByText("Team role: Billing · from your identity provider")).toBeOnTheScreen();
      expect(screen.queryByLabelText(/team role for Al/)).toBeNull();
    });

    it("shows members their teammates' roles, with nothing to change", async () => {
      await open({ ...teamAs("member"), members: [ada, fromIdp] }, { meId: "al" });
      expect(screen.getByText("Team role: Billing · from your identity provider")).toBeOnTheScreen();
      expect(screen.queryByLabelText(/team role for/)).toBeNull();
    });
  });

  describe("requests for team roles (ADR 0263)", () => {
    const request = (id: string, user: TeamMember, hours = 48): RoleRequest => ({
      id,
      role: { id: "r-people", name: "Team people", maxDays: 7, permissions: ["users.manage", "audit.view"], applies: ["users.manage"] },
      scope: "team",
      team: { id: "t1", name: "Alpha" },
      user: { id: user.id, name: user.name ?? user.id, email: user.email ?? null },
      hours,
      reason: "Onboarding week",
      status: "pending",
      createdAt: 1,
      expiresAt: Date.now() + 7 * 86_400_000,
      decidedAt: null,
      decidedBy: null,
      note: null,
      grantedUntil: null,
      current: null,
    });

    it("lets an owner approve a teammate's request for fewer hours, through the team's routes", async () => {
      const { api, user } = await open({ ...teamAs("owner"), roleRequests: 1 }, { requests: [request("rq1", al)] });
      expect(api.teamRoleRequests).toHaveBeenCalledWith("pending");
      const section = within(screen.getByTestId("team-role-requests"));
      expect(section.getByText("Requests for team roles (1)")).toBeOnTheScreen();
      expect(section.getByText("“Onboarding week”")).toBeOnTheScreen();
      await user.press(section.getByRole("radio", { name: "1 day" }));
      await user.type(section.getByLabelText("Note for Al"), "A day is enough");
      await user.press(section.getByLabelText("Approve Al's request"));
      expect(mockConfirm).toHaveBeenCalledWith("Give Team people to Al?", expect.any(String), "Approve");
      expect(api.approveTeamRoleRequest).toHaveBeenCalledWith("rq1", { hours: 24, note: "A day is enough" });
      expect(api.team).toHaveBeenCalledTimes(2);
    });

    it("denies one with a note", async () => {
      const { api, user } = await open({ ...teamAs("admin"), roleRequests: 1 }, { requests: [request("rq1", al)] });
      await user.press(screen.getByLabelText("Deny Al's request"));
      expect(api.denyTeamRoleRequest).toHaveBeenCalledWith("rq1", undefined);
    });

    it("offers only Deny on a request from the team's owners and admins, and nothing on your own", async () => {
      const ev: TeamMember = { ...al, id: "ev", name: "Ev", email: "ev@example.com", role: "admin" };
      const team = { ...teamAs("owner"), roleRequests: 2, members: [ada, al, ev] };
      await open(team, { requests: [request("rq1", ev), request("rq2", ada)] });
      const section = within(screen.getByTestId("team-role-requests"));
      expect(section.getByText(/one of the team's owners or admins/)).toBeOnTheScreen();
      expect(section.queryByLabelText("Approve Ev's request")).toBeNull();
      expect(section.getByLabelText("Deny Ev's request")).toBeOnTheScreen();
      expect(section.getByText("Your own request: another of the team's owners or admins, or a server admin, decides it.")).toBeOnTheScreen();
      expect(section.queryByLabelText("Deny Ada's request")).toBeNull();
    });

    it("says when the requests couldn't be loaded, and loads them again", async () => {
      const api = fakeApi({ ...teamAs("owner"), roleRequests: 1 }, [], [request("rq1", al)]);
      api.teamRoleRequests.mockRejectedValueOnce(new Error("Server busy"));
      const user = userEvent.setup();
      await render(<TeamView api={api as unknown as SuperBotApi} meId="ada" canWrite onBack={jest.fn()} />);
      expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load requests for team roles. Server busy");
      expect(screen.getByText("People")).toBeOnTheScreen();
      await user.press(screen.getByRole("button", { name: "Load requests again" }));
      expect(await screen.findByTestId("team-role-requests")).toBeOnTheScreen();
      expect(screen.queryByText(/Couldn't load requests/)).toBeNull();
    });

    it("asks for none when the team has none waiting, and shows them to nobody who can't decide", async () => {
      const { api } = await open(teamAs("owner"));
      expect(api.teamRoleRequests).not.toHaveBeenCalled();
      expect(screen.queryByTestId("team-role-requests")).toBeNull();
      await open({ ...teamAs("owner"), roleRequests: 1 }, { canWrite: false, requests: [request("rq1", al)] });
      expect(screen.queryByTestId("team-role-requests")).toBeNull();
    });
  });

  it("removes a teammate after a confirmation that says what offboarding removes", async () => {
    const { api, user } = await open(teamAs("owner"));
    await user.press(screen.getByLabelText("Remove Al"));
    expect(api.offboardingPreview).toHaveBeenCalledWith("al");
    const [title, body, label] = mockConfirm.mock.calls[0] as [string, string, string];
    expect(title).toBe("Remove Al from Alpha?");
    expect(label).toBe("Remove");
    expect(body).toContain("2 grants between them and teammates are revoked");
    expect(body).toContain("suspended now and deleted after 7 days");
    expect(body).toContain("their work there goes to the Bots' owner");
    expect(api.removeTeammate).toHaveBeenCalledWith("al");
  });

  it("removes nobody when the confirmation is cancelled", async () => {
    const { api, user } = await open(teamAs("owner"));
    mockConfirm.mockResolvedValueOnce(false);
    await user.press(screen.getByLabelText("Remove Al"));
    expect(api.removeTeammate).not.toHaveBeenCalled();
  });

  it("shows why the server won't remove them, and the server's refusals", async () => {
    const { api, user } = await open(teamAs("owner"));
    api.offboardingPreview.mockResolvedValueOnce({ ...preview, allowed: false, blocked: "owner" });
    await user.press(screen.getByLabelText("Remove Al"));
    expect(await screen.findByText("Only the team's owners can take an owner off the team.")).toBeOnTheScreen();
    expect(mockConfirm).not.toHaveBeenCalled();

    api.removeTeammate.mockRejectedValueOnce(new ApiError("A team needs an owner. Make someone else an owner first.", 409));
    await user.press(screen.getByLabelText("Remove Al"));
    expect(await screen.findByText(/A team needs an owner/)).toBeOnTheScreen();
  });

  it("leaves the team after asking", async () => {
    const { api, user } = await open(teamAs("member"), { meId: "al" });
    await user.press(screen.getByText("Leave team"));
    expect(mockConfirm).toHaveBeenCalledWith("Leave Alpha?", expect.stringContaining("suspended, then deleted"), "Leave");
    expect(api.leaveTeam).toHaveBeenCalled();
  });

  it("offers invites to someone on no team, and joins after saying what changes", async () => {
    const invite: MyTeamInvite = { id: "ti1", team: { id: "t1", name: "Alpha" }, role: "member", expiresAt: Date.UTC(2030, 0, 2) };
    const { api, user } = await open(null, { invites: [invite] });
    expect(screen.getByText("Join a team from one of your invites below.")).toBeOnTheScreen();
    expect(screen.getByRole("heading", { name: "Invites for you" })).toBeOnTheScreen();
    const card = within(screen.getByLabelText("Invite to Alpha"));
    expect(card.getByRole("heading", { name: "Alpha" })).toBeOnTheScreen();
    expect(card.getByRole("button", { name: "Decline invite to Alpha" })).toBeOnTheScreen();
    await user.press(card.getByRole("button", { name: "Join Alpha" }));
    expect(mockConfirm).toHaveBeenCalledWith("Join Alpha?", expect.stringContaining("outside it"), "Join");
    expect(api.acceptTeamInvite).toHaveBeenCalledWith("ti1");
    await user.press(card.getByText("Decline"));
    expect(api.declineTeamInvite).toHaveBeenCalledWith("ti1");
  });

  it("says what to do when you're on no team and have no invites", async () => {
    await open(null);
    expect(screen.getByText("Ask a team's owner or admin to invite you with the email you sign in with.")).toBeOnTheScreen();
    expect(screen.queryByText("Invites for you")).toBeNull();
  });

  it("shows a skeleton while the team loads, and a retry that loads it when it can't", async () => {
    const api = fakeApi(teamAs("member"));
    let fail: (e: Error) => void = () => {};
    api.team.mockImplementationOnce(() => new Promise((_, reject) => (fail = reject)));
    await render(<TeamView api={api as unknown as SuperBotApi} meId="al" canWrite onBack={jest.fn()} />);
    expect(screen.getByRole("progressbar", { name: "Loading your team" })).toBeOnTheScreen();
    await act(async () => fail(new ApiError("HTTP 500", 500)));
    expect(screen.getByRole("alert")).toHaveTextContent(/^Couldn't load your team/);
    expect(screen.getByText("The server had a problem. Try again in a moment.")).toBeOnTheScreen();
    expect(screen.queryByText("You aren't on a team")).toBeNull();
    await userEvent.setup().press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { name: "People" })).toBeOnTheScreen();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("keeps the team on screen when a refresh fails, with a retry", async () => {
    const { api, user } = await open(teamAs("owner"));
    api.team.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await user.press(screen.getByRole("button", { name: "Cancel invite for cy@example.com" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't refresh your team. Can't reach the server. Check your connection and try again.");
    expect(screen.getByText("People")).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Try again" }));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(api.team).toHaveBeenCalledTimes(3);
  });

  it("shows the header's busy dots while a change saves", async () => {
    const { api, user } = await open(teamAs("member"), { meId: "al" });
    let done: () => void = () => {};
    api.leaveTeam.mockImplementationOnce(() => new Promise<void>((r) => (done = r)));
    expect(screen.queryByRole("progressbar")).toBeNull();
    await user.press(screen.getByRole("button", { name: "Leave team" }));
    expect(screen.getByRole("progressbar", { name: "Saving" })).toBeOnTheScreen();
    await act(async () => done());
    expect(screen.queryByRole("progressbar", { name: "Saving" })).toBeNull();
  });

  it("reads the screen's sections as headings, and says when nobody's on the team yet", async () => {
    await open({ ...teamAs("owner"), billing: paying });
    for (const name of ["Plan", "Pro plan", "Invite a teammate", "People"]) expect(screen.getByRole("heading", { name })).toBeOnTheScreen();
    await render(<TeamView api={fakeApi({ ...teamAs("owner"), members: [] }) as unknown as SuperBotApi} meId="ada" canWrite onBack={jest.fn()} />);
    expect(await screen.findByRole("heading", { name: "No one on the team yet" })).toBeOnTheScreen();
    expect(screen.getByText("Invite a teammate above.")).toBeOnTheScreen();
  });

  it("titles the screen with the team's name and goes back to the Bots", async () => {
    const onBack = jest.fn();
    await render(<TeamView api={fakeApi(teamAs("member")) as unknown as SuperBotApi} canWrite onBack={onBack} />);
    expect(await screen.findByRole("header", { name: "Alpha" })).toBeOnTheScreen();
    await userEvent.setup().press(screen.getByRole("button", { name: "Back to Bots" }));
    expect(onBack).toHaveBeenCalled();
  });
});
