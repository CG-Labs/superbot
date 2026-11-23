import {
  baseChangeWarning,
  defaultEnd,
  draftChanges,
  draftError,
  draftOf,
  effectivePermissions,
  emptyDraft,
  endChoices,
  endsAt,
  endsLabel,
  holdersLabel,
  parseMaxDays,
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
    const old = role({ unknown: ["future.perm"] });
    expect(draftChanges(old, { ...draftOf(old), name: "Help desk" })).toEqual({ name: "Help desk", permissions: old.permissions });
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

describe("time-bound roles (ADR 0197)", () => {
  const H = 3_600_000;
  const D = 24 * H;

  it("offers ends within a role's limit, and no end only without one", () => {
    expect(endChoices().map((c) => c.value)).toEqual(["none", "8h", "1d", "7d", "30d", "90d"]);
    expect(endChoices(null)[0]).toEqual({ value: "none", label: "No end" });
    expect(endChoices(7).map((c) => c.value)).toEqual(["8h", "1d", "7d"]);
    expect(endChoices(1).map((c) => c.value)).toEqual(["8h", "1d"]);
    expect(defaultEnd()).toBe("none");
    expect(defaultEnd(30)).toBe("8h");
  });

  it("turns a choice into an end", () => {
    expect(endsAt("none", 1_000)).toBeNull();
    expect(endsAt("8h", 1_000)).toBe(1_000 + 8 * H);
    expect(endsAt("7d", 0)).toBe(7 * D);
    expect(endsAt("nope", 0)).toBeNull();
  });

  it("says when a role ends", () => {
    expect(endsLabel(null, 0)).toBe("");
    expect(endsLabel(undefined, 0)).toBe("");
    expect(endsLabel(0, 1)).toBe("ended");
    expect(endsLabel(30 * 60_000, 0)).toBe("ends within the hour");
    expect(endsLabel(H, 0)).toBe("ends in 1 hour");
    expect(endsLabel(30 * H, 0)).toBe("ends in 30 hours");
    expect(endsLabel(3 * D, 0)).toBe("ends in 3 days");
  });

  it("reads a limit as the server checks it", () => {
    expect(parseMaxDays("")).toBeNull();
    expect(parseMaxDays(" 7 ")).toBe(7);
    expect(parseMaxDays("365")).toBe(365);
    for (const bad of ["0", "366", "1.5", "-1", "a week"]) expect(parseMaxDays(bad)).toBeUndefined();
  });

  it("sends a new limit only when it changed", () => {
    const r = role({ maxDays: 7 });
    expect(draftOf(r).maxDays).toBe(7);
    expect(draftChanges(r, draftOf(r))).toBeNull();
    expect(draftChanges(r, { ...draftOf(r), maxDays: null })).toEqual({ maxDays: null });
    expect(draftChanges(r, { ...draftOf(r), maxDays: undefined })).toBeNull();
    expect(draftChanges(role(), { ...draftOf(role()), maxDays: 30 })).toEqual({ maxDays: 30 });
    expect(draftChanges(role(), draftOf(role()))).toBeNull();
  });
});
