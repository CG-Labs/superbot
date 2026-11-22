import {
  baseChangeWarning,
  draftChanges,
  draftError,
  draftOf,
  effectivePermissions,
  emptyDraft,
  holdersLabel,
  permissionLabel,
  teamPermissions,
  togglePermission,
} from "../roles";
import type { CustomRole, RolesView } from "../types";

const VIEW: RolesView = {
  permissions: [
    { name: "users.manage", description: "Manage people and sessions", team: true },
    { name: "bots.manage", description: "Manage people's Bots", team: false },
    { name: "audit.view", description: "See the audit log", team: false },
    { name: "billing.manage", description: "See usage and plans", team: true },
    { name: "signups.approve", description: "Approve sign-ups", team: false },
    { name: "machines.manage", description: "Run machines", team: true },
  ],
  builtIn: [
    {
      id: "admin",
      name: "Admin",
      builtIn: true,
      permissions: ["account", "read", "review", "write", "approve", "admin", "users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"],
    },
    { id: "member", name: "Member", builtIn: true, permissions: ["account", "read", "review", "write", "approve"] },
    { id: "readonly", name: "Read-only", builtIn: true, permissions: ["account", "read", "review"] },
  ],
  roles: [],
};

const role = (r: Partial<CustomRole> = {}): CustomRole => ({
  id: "r1",
  name: "Support",
  description: "",
  base: "member",
  builtIn: false,
  permissions: ["users.manage"],
  unknown: [],
  effective: [],
  users: 0,
  teamMembers: 0,
  createdAt: 0,
  createdBy: null,
  updatedAt: 0,
  ...r,
});

describe("custom roles (ADR 0123, 0132)", () => {
  it("toggles permissions and keeps the server's order", () => {
    expect(togglePermission(VIEW, [], "audit.view")).toEqual(["audit.view"]);
    expect(togglePermission(VIEW, ["machines.manage"], "users.manage")).toEqual(["users.manage", "machines.manage"]);
    expect(togglePermission(VIEW, ["users.manage", "machines.manage"], "users.manage")).toEqual(["machines.manage"]);
    // Names the server doesn't offer are dropped, so a draft never sends one.
    expect(togglePermission(VIEW, ["secrets.manage"], "audit.view")).toEqual(["audit.view"]);
  });

  it("shows what a role adds up to, as the server lists it", () => {
    expect(effectivePermissions(VIEW, "readonly", ["audit.view"])).toEqual(["account", "read", "review", "audit.view"]);
    expect(effectivePermissions(VIEW, "member", ["machines.manage", "users.manage"])).toEqual(["account", "read", "review", "write", "approve", "users.manage", "machines.manage"]);
    expect(effectivePermissions(VIEW, "member", ["admin"])).toEqual(["account", "read", "review", "write", "approve"]);
  });

  it("applies only team permissions within a team", () => {
    expect(teamPermissions(VIEW, ["users.manage", "audit.view", "machines.manage"])).toEqual(["users.manage", "machines.manage"]);
    expect(teamPermissions(VIEW, ["audit.view"])).toEqual([]);
  });

  it("names permissions in words", () => {
    expect(permissionLabel(VIEW, "audit.view")).toBe("See the audit log");
    expect(permissionLabel(VIEW, "write")).toBe("Use Bots");
    expect(permissionLabel(VIEW, "future.thing")).toBe("future.thing");
  });

  it("checks names as the server does", () => {
    const view = { roles: [role()] };
    expect(draftError(view, emptyDraft())).toBe("Give the role a name.");
    expect(draftError(view, { ...emptyDraft(), name: " Read-only " })).toMatch(/built-in/);
    expect(draftError(view, { ...emptyDraft(), name: "support" })).toMatch(/exists already/);
    expect(draftError(view, { ...emptyDraft(), name: "support" }, "r1")).toBeNull();
    expect(draftError(view, { ...emptyDraft(), name: "x".repeat(61) })).toMatch(/60/);
    expect(draftError(view, { ...emptyDraft(), name: "Auditor", description: "x".repeat(501) })).toMatch(/500/);
    expect(draftError(view, { ...emptyDraft(), name: "Auditor" })).toBeNull();
  });

  it("sends only what changed", () => {
    const r = role({ description: "Helpdesk" });
    expect(draftChanges(r, draftOf(r))).toBeNull();
    expect(draftChanges(r, { ...draftOf(r), permissions: ["users.manage"] })).toBeNull();
    expect(draftChanges(r, { ...draftOf(r), name: " Help desk ", base: "readonly" })).toEqual({ name: "Help desk", base: "readonly" });
    expect(draftChanges(r, { ...draftOf(r), permissions: [] })).toEqual({ permissions: [] });
    expect(draftChanges(r, { ...draftOf(r), description: "" })).toEqual({ description: "" });
  });

  it("warns before a new base moves the people who have it", () => {
    expect(baseChangeWarning(role({ users: 2 }), draftOf(role()))).toBeNull();
    expect(baseChangeWarning(role(), { ...draftOf(role()), base: "readonly" })).toBeNull();
    expect(baseChangeWarning(role({ users: 1 }), { ...draftOf(role()), base: "readonly" })).toBe(
      "The 1 person who has it across the server moves to Read-only at once. Read-only people change nothing, so team roles they hold stop working.",
    );
    expect(baseChangeWarning(role({ users: 3, base: "readonly" }), { ...draftOf(role()), base: "member" })).toBe("The 3 people who have it across the server move to Member at once.");
  });

  it("counts who has it", () => {
    expect(holdersLabel({ users: 0, teamMembers: 0 })).toBe("Nobody has it");
    expect(holdersLabel({ users: 1, teamMembers: 0 })).toBe("1 person");
    expect(holdersLabel({ users: 2, teamMembers: 1 })).toBe("2 people · 1 in a team");
    expect(holdersLabel({ users: 0, teamMembers: 3 })).toBe("3 in a team");
  });
});
