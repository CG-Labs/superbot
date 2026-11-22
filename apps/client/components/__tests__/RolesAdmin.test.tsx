import React from "react";
import { render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { RolesAdmin } from "../RolesAdmin";
import type { SuperBotApi } from "../../src/api";
import type { AdminUser, CustomRole, RolesView, Team } from "../../src/types";

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
    role: jest.fn(async () => ({ ...SUPPORT, holders: { users: [{ id: "u0", name: "Sam", email: "sam@example.com" }], teams: [{ team: { id: "t1", name: "Ops" }, user: { id: "u1", name: "Bo", email: "bo@example.com" } }] } })),
    users: jest.fn(async () => [user("u0", "Sam"), user("u2", "Ada", "admin"), user("u3", "Cy"), user("u4", "Rex", "readonly"), user("me", "Me", "admin")]),
    teams: jest.fn(async () => [TEAM]),
    createRole: jest.fn(async () => ({ ...SUPPORT, id: "r2", name: "Auditor" })),
    updateRole: jest.fn(async () => SUPPORT),
    deleteRole: jest.fn(async () => {}),
    assignRole: jest.fn(async () => ({})),
    unassignRole: jest.fn(async () => {}),
    assignTeamRole: jest.fn(async () => ({ applies: ["users.manage"] })),
    unassignTeamRole: jest.fn(async () => {}),
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
    await waitFor(() => expect(api.assignRole).toHaveBeenCalledWith("r1", "u2"));

    await u.press(screen.getByLabelText("Take away from Sam"));
    await waitFor(() => expect(api.unassignRole).toHaveBeenCalledWith("r1", "u0"));

    // Bo has it in Ops already; read-only Rex can't use it.
    expect(screen.queryByLabelText("Give to Bo in Ops")).toBeNull();
    expect(screen.getByLabelText("Give to Rex in Ops")).toBeDisabled();
    await u.press(screen.getByLabelText("Give to Cy in Ops"));
    await waitFor(() => expect(api.assignTeamRole).toHaveBeenCalledWith("r1", "t1", "u3"));
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
