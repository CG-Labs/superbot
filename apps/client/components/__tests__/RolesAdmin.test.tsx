import React from "react";
import { render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { RolesAdmin } from "../RolesAdmin";
import { ApiError, type SuperBotApi } from "../../src/api";
import type { AdminUser, CustomRole, RoleRequest, RolesView, Team } from "../../src/types";

jest.mock("../../src/dialogs", () => ({ confirmAsync: jest.fn(async () => true) }));

const SUPPORT: CustomRole = {
  id: "r1",
  name: "Support",
  description: "Helpdesk",
  base: "member",
  builtIn: false,
  permissions: ["users.manage"],
  unknown: [],
  effective: ["account", "read", "review", "write", "approve", "users.manage"],
  users: 1,
  teamMembers: 1,
  createdAt: 0,
  createdBy: null,
  updatedAt: 1,
};

const VIEW: RolesView = {
  permissions: [
    { name: "users.manage", description: "Manage people and sessions", team: true },
    { name: "audit.view", description: "See the audit log", team: false },
  ],
  builtIn: [
    { id: "admin", name: "Admin", builtIn: true, permissions: ["account", "read", "review", "write", "approve", "admin", "users.manage", "audit.view"] },
    { id: "member", name: "Member", builtIn: true, permissions: ["account", "read", "review", "write", "approve"] },
    { id: "readonly", name: "Read-only", builtIn: true, permissions: ["account", "read", "review"] },
  ],
  roles: [SUPPORT],
};

const user = (id: string, name: string, role: AdminUser["role"] = "member"): AdminUser => ({ id, name, email: `${name.toLowerCase()}@example.com`, role, status: "active", breakGlass: false, createdAt: 0, updatedAt: 0 });
const TEAM: Team = {
  id: "t1",
  name: "Ops",
  machines: false,
  createdAt: 0,
  members: [
    { id: "u1", name: "Bo", email: "bo@example.com", role: "member", joinedAt: 0, active: true, customRole: { id: "r1", name: "Support" } },
    { id: "u3", name: "Cy", email: "cy@example.com", role: "member", joinedAt: 0, active: true },
    { id: "u4", name: "Rex", email: "rex@example.com", role: "member", joinedAt: 0, active: true },
  ],
};

function mockApi() {
  return {
    roles: jest.fn(async () => VIEW),
    role: jest.fn(async (): Promise<CustomRole> => ({ ...SUPPORT, holders: { users: [{ id: "u0", name: "Sam", email: "sam@example.com" }], teams: [{ team: { id: "t1", name: "Ops" }, user: { id: "u1", name: "Bo", email: "bo@example.com" } }] } })),
    users: jest.fn(async () => [user("u0", "Sam"), user("u2", "Ada", "admin"), user("u3", "Cy"), user("u4", "Rex", "readonly"), user("me", "Me", "admin")]),
    teams: jest.fn(async () => [TEAM]),
    createRole: jest.fn(async () => ({ ...SUPPORT, id: "r2", name: "Auditor" })),
    updateRole: jest.fn(async () => SUPPORT),
    deleteRole: jest.fn(async () => {}),
    assignRole: jest.fn(async () => ({})),
    unassignRole: jest.fn(async () => {}),
    assignTeamRole: jest.fn(async () => ({ applies: ["users.manage"] })),
    unassignTeamRole: jest.fn(async () => {}),
    roleRequests: jest.fn(async () => ({ requests: [] as RoleRequest[], pending: 0, pendingDays: 7 })),
    approveRoleRequest: jest.fn(async () => ({})),
    denyRoleRequest: jest.fn(async () => ({})),
  };
}

const show = (api: ReturnType<typeof mockApi>) => render(<RolesAdmin api={api as unknown as SuperBotApi} meId="me" onBack={jest.fn()} />);

describe("RolesAdmin (ADR 0132)", () => {
  it("builds a role from the fixed permissions and shows what it adds up to", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await screen.findByLabelText("Role Support");
    expect(screen.getByLabelText("Role Read-only")).toBeTruthy();

    await u.press(screen.getByLabelText("New role"));
    await u.type(screen.getByLabelText("Role name"), "Auditor");
    await u.press(screen.getByRole("radio", { name: "Read-only" }));
    await u.press(screen.getByRole("checkbox", { name: "audit.view" }));
    // Read-only's preset plus the permission: in the list and in what it can do.
    expect(screen.getAllByText("See the audit log")).toHaveLength(2);
    expect(screen.getByText("See approvals")).toBeTruthy();
    expect(screen.queryByText("Use Bots")).toBeNull();
    expect(screen.getByText("Within a team: nothing (it has no team permissions).")).toBeTruthy();
    await u.press(screen.getByLabelText("Create role"));
    expect(api.createRole).toHaveBeenCalledWith({ name: "Auditor", description: "", base: "readonly", permissions: ["audit.view"] });
  });

  it("refuses a built-in name before sending it", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New role"));
    await u.type(screen.getByLabelText("Role name"), "admin");
    expect(screen.getByText(/built-in role's name/)).toBeTruthy();
    await u.press(screen.getByLabelText("Create role"));
    expect(api.createRole).not.toHaveBeenCalled();
  });

  it("gives a role across the server and within a team, and takes it away", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    await screen.findByLabelText("Take away from Sam");
    // Held, so it can't be deleted yet.
    expect(screen.getByLabelText("Delete")).toBeDisabled();

    await u.type(screen.getByLabelText("Search people to give the role to"), "a");
    expect(screen.queryByLabelText("Give to Sam")).toBeNull();
    expect(screen.getByLabelText("Give to Me")).toBeDisabled();
    await u.press(screen.getByLabelText("Give to Ada"));
    await waitFor(() => expect(api.assignRole).toHaveBeenCalledWith("r1", "u2", undefined));

    await u.press(screen.getByLabelText("Take away from Sam"));
    await waitFor(() => expect(api.unassignRole).toHaveBeenCalledWith("r1", "u0"));

    // Bo has it in Ops already; read-only Rex can't use it.
    expect(screen.queryByLabelText("Give to Bo in Ops")).toBeNull();
    expect(screen.getByLabelText("Give to Rex in Ops")).toBeDisabled();
    await u.press(screen.getByLabelText("Give to Cy in Ops"));
    await waitFor(() => expect(api.assignTeamRole).toHaveBeenCalledWith("r1", "t1", "u3", undefined));
    await u.press(screen.getByLabelText("Take away from Bo in Ops"));
    await waitFor(() => expect(api.unassignTeamRole).toHaveBeenCalledWith("r1", "t1", "u1"));
  });

  it("saves only what changed", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    expect(screen.getByLabelText("Save")).toBeDisabled();
    await u.press(screen.getByRole("checkbox", { name: "audit.view" }));
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateRole).toHaveBeenCalledWith("r1", { permissions: ["users.manage", "audit.view"] }));
  });
});

describe("RolesAdmin: time-bound roles (ADR 0197)", () => {
  const NOW = Date.UTC(2026, 10, 23, 12);
  beforeEach(() => jest.spyOn(Date, "now").mockReturnValue(NOW));
  afterEach(() => jest.restoreAllMocks());

  it("makes a role time-bound, and checks the limit first", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New role"));
    await u.type(screen.getByLabelText("Role name"), "Break glass");
    await u.type(screen.getByLabelText("Most days it can be given for"), "400");
    expect(screen.getByText(/1 to 365 days/)).toBeTruthy();
    expect(screen.getByLabelText("Create role")).toBeDisabled();
    await u.clear(screen.getByLabelText("Most days it can be given for"));
    await u.type(screen.getByLabelText("Most days it can be given for"), "7");
    expect(screen.getByText(/at most 7 days at a time/)).toBeTruthy();
    await u.press(screen.getByLabelText("Create role"));
    expect(api.createRole).toHaveBeenCalledWith({ name: "Break glass", description: "", base: "member", permissions: [], maxDays: 7 });
  });

  it("gives a time-bound role with an end within its limit and a reason, and shows when it ends", async () => {
    const api = mockApi();
    const timeBound = { ...SUPPORT, maxDays: 7 };
    api.roles.mockResolvedValue({ ...VIEW, roles: [timeBound] });
    api.role.mockResolvedValue({
      ...timeBound,
      holders: {
        users: [{ id: "u0", name: "Sam", email: "sam@example.com", expiresAt: NOW + 3 * 86_400_000 }],
        teams: [{ team: { id: "t1", name: "Ops" }, user: { id: "u1", name: "Bo", email: "bo@example.com" }, expiresAt: NOW + 5 * 3_600_000 }],
      },
    });
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    await screen.findByLabelText("Take away from Sam");
    expect(screen.getByText(/ends in 3 days/)).toBeTruthy();
    expect(screen.getByText(/ends in 5 hours/)).toBeTruthy();
    // Never "No end", nor longer than its limit; the shortest is picked.
    expect(screen.queryByRole("radio", { name: "No end" })).toBeNull();
    expect(screen.queryByRole("radio", { name: "30 days" })).toBeNull();
    expect(screen.getByRole("radio", { name: "8 hours" })).toBeChecked();
    await u.press(screen.getByRole("radio", { name: "7 days" }));
    await u.type(screen.getByLabelText("Why it's given"), "Incident 42");
    await u.type(screen.getByLabelText("Search people to give the role to"), "a");
    await u.press(screen.getByLabelText("Give to Ada"));
    await waitFor(() => expect(api.assignRole).toHaveBeenCalledWith("r1", "u2", { expiresAt: NOW + 7 * 86_400_000, reason: "Incident 42" }));
    await u.press(screen.getByLabelText("Give to Cy in Ops"));
    await waitFor(() => expect(api.assignTeamRole).toHaveBeenCalledWith("r1", "t1", "u3", { expiresAt: NOW + 7 * 86_400_000 }));
  });

  it("changes when a holder's role ends without taking it away", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    await u.press(await screen.findByRole("radio", { name: "30 days" }));
    await u.press(screen.getByLabelText("Change end for Sam"));
    await waitFor(() => expect(api.assignRole).toHaveBeenCalledWith("r1", "u0", { expiresAt: NOW + 30 * 86_400_000 }));
    await u.press(screen.getByRole("radio", { name: "No end" }));
    await u.press(screen.getByLabelText("Change end for Bo in Ops"));
    await waitFor(() => expect(api.assignTeamRole).toHaveBeenCalledWith("r1", "t1", "u1", undefined));
    expect(api.unassignRole).not.toHaveBeenCalled();
  });

  it("lifts a limit", async () => {
    const api = mockApi();
    api.roles.mockResolvedValue({ ...VIEW, roles: [{ ...SUPPORT, maxDays: 7 }] });
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    await u.clear(screen.getByLabelText("Most days it can be given for"));
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateRole).toHaveBeenCalledWith("r1", { maxDays: null }));
  });
});

describe("RolesAdmin: requests for roles (ADR 0209)", () => {
  const NOW = Date.UTC(2026, 10, 23, 12);
  beforeEach(() => jest.spyOn(Date, "now").mockReturnValue(NOW));
  afterEach(() => jest.restoreAllMocks());

  const request = (r: Partial<RoleRequest> = {}): RoleRequest => ({
    id: "q1",
    role: { id: "r1", name: "Support", maxDays: 1, permissions: ["users.manage"], applies: ["users.manage"] },
    scope: "org",
    team: null,
    user: { id: "u3", name: "Cy", email: "cy@example.com" },
    hours: 8,
    reason: "Incident 42",
    status: "pending",
    createdAt: NOW,
    expiresAt: NOW + 7 * 86_400_000,
    decidedAt: null,
    decidedBy: null,
    note: null,
    grantedUntil: null,
    current: null,
    ...r,
  });

  it("makes a time-bound role requestable, and never one with no limit", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New role"));
    await u.type(screen.getByLabelText("Role name"), "On-call");
    expect(screen.getByRole("checkbox", { name: "People may request it" })).toBeDisabled();
    await u.type(screen.getByLabelText("Most days it can be given for"), "1");
    await u.press(screen.getByRole("checkbox", { name: "People may request it" }));
    await u.press(screen.getByLabelText("Create role"));
    expect(api.createRole).toHaveBeenCalledWith({ name: "On-call", description: "", base: "member", permissions: [], maxDays: 1, requestable: true });
  });

  it("stops a role being requestable when its limit is lifted", async () => {
    const api = mockApi();
    api.roles.mockResolvedValue({ ...VIEW, roles: [{ ...SUPPORT, maxDays: 7, requestable: true }] });
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    expect(screen.getByRole("checkbox", { name: "People may request it" })).toBeChecked();
    await u.clear(screen.getByLabelText("Most days it can be given for"));
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateRole).toHaveBeenCalledWith("r1", { maxDays: null, requestable: false }));
  });

  it("approves a pending request for less than asked, or denies it with a note", async () => {
    const api = mockApi();
    api.roleRequests.mockResolvedValue({ requests: [request(), request({ id: "q2", user: { id: "u4", name: "Rex", email: "rex@example.com" }, team: { id: "t1", name: "Ops" }, scope: "team" })], pending: 2, pendingDays: 7 });
    const u = userEvent.setup();
    await show(api);
    expect(await screen.findByText("Requests (2)")).toBeTruthy();
    expect(screen.getByText("Cy (cy@example.com) asks for Support for 8 hours, across the server")).toBeTruthy();
    expect(screen.getByText("Rex (rex@example.com) asks for Support for 8 hours, in Ops")).toBeTruthy();
    expect(screen.getAllByText("“Incident 42”")).toHaveLength(2);
    // As asked, or shorter: never longer.
    expect(screen.queryByRole("radio", { name: "1 day" })).toBeNull();
    await u.press(screen.getAllByRole("radio", { name: "4 hours" })[0]);
    await u.press(screen.getByLabelText("Approve Cy's request"));
    await waitFor(() => expect(api.approveRoleRequest).toHaveBeenCalledWith("q1", { hours: 4, note: undefined }));
    await u.type(screen.getByLabelText("Note for Rex"), "Use the runbook");
    await u.press(screen.getByLabelText("Deny Rex's request"));
    await waitFor(() => expect(api.denyRoleRequest).toHaveBeenCalledWith("q2", "Use the runbook"));
  });

  it("says when requests didn't load, and tries again; an older server has none", async () => {
    const api = mockApi();
    api.roleRequests.mockRejectedValueOnce(new ApiError("Server error", 500));
    api.roleRequests.mockResolvedValueOnce({ requests: [request()], pending: 1, pendingDays: 7 });
    const u = userEvent.setup();
    await show(api);
    expect(await screen.findByText("Couldn't load requests for roles: Server error")).toBeTruthy();
    await u.press(screen.getByLabelText("Load requests again"));
    expect(await screen.findByText("Requests (1)")).toBeTruthy();
    expect(screen.queryByText(/Couldn't load requests/)).toBeNull();
  });

  it("shows nothing for requests on a server from before them", async () => {
    const api = mockApi();
    api.roleRequests.mockRejectedValue(new ApiError("Not found", 404));
    await show(api);
    await screen.findByLabelText("Role Support");
    expect(screen.queryByText(/Couldn't load requests/)).toBeNull();
  });

  it("leaves your own request to another admin", async () => {
    const api = mockApi();
    api.roleRequests.mockResolvedValue({ requests: [request({ user: { id: "me", name: "Me", email: "me@example.com" } })], pending: 1, pendingDays: 7 });
    await show(api);
    expect(await screen.findByText(/another admin decides it/)).toBeTruthy();
    expect(screen.queryByLabelText("Approve Me's request")).toBeNull();
  });
});

describe("RolesAdmin: two approvers for chosen roles (ADR 0320)", () => {
  const NOW = Date.UTC(2026, 10, 26, 12);
  beforeEach(() => jest.spyOn(Date, "now").mockReturnValue(NOW));
  afterEach(() => jest.restoreAllMocks());

  const request = (r: Partial<RoleRequest> = {}): RoleRequest => ({
    id: "q1",
    role: { id: "r1", name: "Root", maxDays: 1, permissions: ["machines.manage"], applies: ["machines.manage"] },
    scope: "org",
    team: null,
    user: { id: "u3", name: "Cy", email: "cy@example.com" },
    hours: 8,
    reason: "Rotate keys",
    status: "pending",
    createdAt: NOW,
    expiresAt: NOW + 7 * 86_400_000,
    decidedAt: null,
    decidedBy: null,
    note: null,
    grantedUntil: null,
    current: null,
    approvals: 2,
    firstApproval: null,
    ...r,
  });
  const first = { by: { id: "u2", name: "Ada", email: "ada@example.com" }, at: NOW - 60_000, hours: 4, note: "Fine by me" };

  it("makes a requestable role need two approvers, and only a requestable one", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New role"));
    await u.type(screen.getByLabelText("Role name"), "Root");
    expect(screen.getByRole("checkbox", { name: "Needs two approvers" })).toBeDisabled();
    await u.type(screen.getByLabelText("Most days it can be given for"), "1");
    expect(screen.getByRole("checkbox", { name: "Needs two approvers" })).toBeDisabled();
    await u.press(screen.getByRole("checkbox", { name: "People may request it" }));
    await u.press(screen.getByRole("checkbox", { name: "Needs two approvers" }));
    await u.press(screen.getByLabelText("Create role"));
    expect(api.createRole).toHaveBeenCalledWith({ name: "Root", description: "", base: "member", permissions: [], maxDays: 1, requestable: true, approvals: 2 });
  });

  it("goes back to one approver when people may no longer request it", async () => {
    const api = mockApi();
    api.roles.mockResolvedValue({ ...VIEW, roles: [{ ...SUPPORT, maxDays: 7, requestable: true, approvals: 2 }] });
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Role Support"));
    expect(screen.getByRole("checkbox", { name: "Needs two approvers" })).toBeChecked();
    await u.press(screen.getByRole("checkbox", { name: "People may request it" }));
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateRole).toHaveBeenCalledWith("r1", { requestable: false, approvals: 1 }));
  });

  it("gives the first of two approvals, saying nothing is given yet", async () => {
    const api = mockApi();
    api.roleRequests.mockResolvedValue({ requests: [request()], pending: 1, pendingDays: 7 });
    const u = userEvent.setup();
    await show(api);
    expect(await screen.findByText(/Waiting for two approvers · lapses in 7 days/)).toBeTruthy();
    expect(screen.getByText("Approve (1 of 2)")).toBeTruthy();
    await u.press(screen.getByRole("radio", { name: "4 hours" }));
    await u.press(screen.getByLabelText("Approve Cy's request"));
    await waitFor(() => expect(api.approveRoleRequest).toHaveBeenCalledWith("q1", { hours: 4, note: undefined }));
    const { confirmAsync } = jest.requireMock("../../src/dialogs");
    expect(confirmAsync).toHaveBeenLastCalledWith("Approve Cy's request for Root?", expect.stringContaining("Yours is the first"), "Approve");
  });

  it("gives the second for the first's hours or fewer", async () => {
    const api = mockApi();
    api.roleRequests.mockResolvedValue({ requests: [request({ firstApproval: first })], pending: 1, pendingDays: 7 });
    const u = userEvent.setup();
    await show(api);
    expect(await screen.findByText(/Approved once, waiting for a second approver/)).toBeTruthy();
    expect(screen.getByText("First approved by Ada for 4 hours: “Fine by me”.")).toBeTruthy();
    expect(screen.getByRole("radio", { name: "4 hours (as first approved)" })).toBeTruthy();
    expect(screen.queryByRole("radio", { name: /8 hours/ })).toBeNull();
    expect(screen.getByText("Approve")).toBeTruthy();
    await u.press(screen.getByLabelText("Approve Cy's request"));
    await waitFor(() => expect(api.approveRoleRequest).toHaveBeenCalledWith("q1", { hours: 4, note: undefined }));
  });

  it("leaves the second approval to someone else, but lets the first approver deny", async () => {
    const api = mockApi();
    api.roleRequests.mockResolvedValue({ requests: [request({ firstApproval: { ...first, by: { id: "me", name: "Me" } } })], pending: 1, pendingDays: 7 });
    const u = userEvent.setup();
    await show(api);
    expect(await screen.findByText("You gave the first approval. Someone else gives the second.")).toBeTruthy();
    expect(screen.queryByLabelText("Approve Cy's request")).toBeNull();
    await u.press(screen.getByLabelText("Deny Cy's request"));
    await waitFor(() => expect(api.denyRoleRequest).toHaveBeenCalledWith("q1", undefined));
  });
});
