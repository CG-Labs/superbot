import React from "react";
import { render, screen, userEvent, within } from "@testing-library/react-native";
import { TeamView } from "../TeamView";
import { ApiError, type SuperBotApi } from "../../src/api";
import type { MyTeamInvite, OffboardingPreview, Team, TeamMember } from "../../src/types";

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

function fakeApi(team: Team | null, invites: MyTeamInvite[] = []) {
  return {
    team: jest.fn(async () => team),
    myTeamInvites: jest.fn(async () => invites),
    inviteToTeam: jest.fn(async () => ({})),
    cancelTeamInvite: jest.fn(async () => {}),
    setTeamRole: jest.fn(async () => ({})),
    offboardingPreview: jest.fn(async (): Promise<OffboardingPreview> => preview),
    removeTeammate: jest.fn(async () => {}),
    leaveTeam: jest.fn(async () => {}),
    acceptTeamInvite: jest.fn(async () => {}),
    declineTeamInvite: jest.fn(async () => {}),
  };
}

async function open(team: Team | null, { meId = "ada", canWrite = true, invites = [] as MyTeamInvite[] } = {}) {
  const api = fakeApi(team, invites);
  const user = userEvent.setup();
  await render(<TeamView api={api as unknown as SuperBotApi} meId={meId} canWrite={canWrite} onBack={jest.fn()} />);
  await screen.findByText(team ? "People" : "You aren't on a team.");
  return { api, user };
}

beforeEach(() => mockConfirm.mockClear());

describe("TeamView", () => {
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
    const card = within(screen.getByLabelText("Invite to Alpha"));
    await user.press(card.getByText("Join"));
    expect(mockConfirm).toHaveBeenCalledWith("Join Alpha?", expect.stringContaining("outside it"), "Join");
    expect(api.acceptTeamInvite).toHaveBeenCalledWith("ti1");
    await user.press(card.getByText("Decline"));
    expect(api.declineTeamInvite).toHaveBeenCalledWith("ti1");
  });
});
