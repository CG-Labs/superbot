import {
  botAccessLabel,
  csvFileName,
  effectiveLabel,
  flags,
  groupLabel,
  lastLoginLabel,
  machineLabel,
  ownerLabel,
  serviceFlags,
  serviceRoleLabel,
  serviceTokenLabel,
  signInsLabel,
} from "../accessReview";
import type { AccessReviewPerson, AccessReviewServiceAccount, AccessReviewServiceToken, AccessReviewSession } from "../types";

const session = (id: string, kind: string): AccessReviewSession => ({ id, kind, method: "code", createdAt: 0, lastSeenAt: 0, endsAt: 1 });

const person = (p: Partial<AccessReviewPerson> = {}): AccessReviewPerson => ({
  id: "u1",
  name: "Ada",
  email: "ada@example.com",
  role: "member",
  status: "active",
  breakGlass: false,
  createdAt: 0,
  scim: null,
  team: null,
  mfa: { enabled: true, enabledAt: 1 },
  lastLogin: null,
  botAccess: { all: false, bots: [] },
  sessions: [],
  apiTokens: [],
  machine: null,
  ...p,
});

describe("access review labels", () => {
  it("names each group by tenant and team", () => {
    expect(groupLabel({ tenant: null, team: null, people: [] })).toBe("No team, not from SCIM");
    expect(groupLabel({ tenant: "okta", team: { id: "t1", name: "Research" }, people: [] })).toBe("SCIM: okta · Team: Research");
    expect(groupLabel({ tenant: null, team: { id: "t1", name: "Research" }, people: [] })).toBe("Team: Research");
  });

  it("flags what a reviewer should look at twice", () => {
    expect(flags(person())).toEqual([]);
    expect(flags(person({ role: "admin", mfa: { enabled: false, enabledAt: null }, breakGlass: true }))).toEqual(["Owner (break-glass)", "Admin", "No second factor"]);
    expect(flags(person({ status: "disabled", role: "admin", mfa: { enabled: false, enabledAt: null }, apiTokens: [session("s1", "token")], scim: { tenant: "okta", deleted: true } }))).toEqual([
      "Disabled",
      "Deleted in okta",
      "Still signed in",
    ]);
    expect(flags(person({ scim: { tenant: "entra", deleted: false } }))).toEqual(["SCIM: entra"]);
  });

  it("says how and when they last signed in", () => {
    const date = (ms: number) => `t${ms}`;
    expect(lastLoginLabel(person(), date)).toBe("Never signed in");
    expect(lastLoginLabel(person({ lastLogin: { at: 5, method: "sso", idpProvider: "work" } }), date)).toBe("SSO · work, t5");
    expect(lastLoginLabel(person({ lastLogin: { at: 5, method: "code", idpProvider: null } }), date)).toBe("Sign-in code, t5");
    expect(lastLoginLabel(person({ lastLogin: { at: 5, method: null, idpProvider: null } }), date)).toBe("t5");
  });

  it("lists Bot access, sign-ins and the machine", () => {
    expect(botAccessLabel(person({ botAccess: { all: true, bots: [] } }))).toBe("All Bots (admin)");
    expect(botAccessLabel(person())).toBe("No Bots");
    const bots = [
      { id: "b1", name: "Scout", owner: { id: "u1", name: "Ada" }, own: true, visibility: "private", access: "manage", grant: null },
      { id: "b2", name: "Ledger", owner: { id: "u2", name: null }, own: false, visibility: "private", access: "operate", grant: "operator" },
    ];
    expect(botAccessLabel(person({ botAccess: { all: false, bots } }))).toBe("Scout (manage, own); Ledger (operate, u2's, granted operator)");
    expect(signInsLabel(person())).toBe("Not signed in");
    expect(signInsLabel(person({ apiTokens: [session("a", "token"), session("b", "token")], sessions: [session("c", "cookie")] }))).toBe("2 API tokens, 1 browser session");
    expect(machineLabel(person())).toBe("No machine");
    expect(machineLabel(person({ machine: { id: "m1", provider: "incus", state: "running", enrollment: "enrolled", assignedAt: 3 } }))).toBe("running, Bots run on it");
  });

  it("words a service account's owner, roles, flags and tokens", () => {
    const sa = (p: Partial<AccessReviewServiceAccount> = {}): AccessReviewServiceAccount => ({
      id: "sa1",
      name: "CI",
      description: "",
      role: "member",
      status: "active",
      createdAt: 0,
      createdBy: null,
      customRole: null,
      team: null,
      owner: { id: "u1", name: "Ada", email: "ada@example.com", status: "active" },
      ownerActive: true,
      permissions: ["account", "read"],
      teamPermissions: [],
      effective: ["account", "read"],
      botAccess: { all: false, bots: [] },
      tokens: [],
      flags: [],
      ...p,
    });
    expect(ownerLabel(sa())).toBe("Ada");
    expect(ownerLabel(sa({ ownerActive: false }))).toBe("Ada (inactive)");
    expect(ownerLabel(sa({ owner: null }))).toBe("No owner");
    expect(serviceRoleLabel(sa())).toBe("member");
    expect(serviceRoleLabel(sa({ role: "readonly", customRole: { id: "r1", name: "Exporter", permissions: [] } }))).toBe("readonly · Exporter");
    const team = { id: "t1", name: "Alpha", role: "member", customRole: { id: "r2", name: "Ops", permissions: [] } };
    expect(serviceRoleLabel(sa({ team }))).toBe("member · Ops, in Alpha");
    expect(serviceRoleLabel(sa({ team, ownerOnTeam: true }))).toBe("member · Ops, in Alpha");
    expect(serviceRoleLabel(sa({ team, ownerOnTeam: false }))).toBe("member · Ops, in Alpha (acts in no team)");
    expect(effectiveLabel(sa())).toBe("account, read");
    expect(effectiveLabel(sa({ effective: [] }))).toBe("Nothing");
    expect(serviceFlags(sa({ flags: ["owner_inactive", "owner_off_team", "unscoped_token", "unused_token", "disabled", "new_one"] }))).toEqual([
      "Owner inactive",
      "Owner off its team",
      "Token with everything",
      "Token unused 90 days",
      "Disabled",
      "new_one",
    ]);
    const t: AccessReviewServiceToken = { id: "st1", name: "Nightly", preview: "sbsa_…ab12", scopes: ["read", "write"], createdAt: 0, expiresAt: 9, lastUsedAt: 5, replaced: false };
    const date = (ms: number) => `t${ms}`;
    expect(serviceTokenLabel(t, date)).toBe("Nightly sbsa_…ab12: read, write; expires t9; last used t5");
    expect(serviceTokenLabel({ ...t, scopes: null, lastUsedAt: null, replaced: true }, date)).toBe("Nightly sbsa_…ab12: everything it holds; replaced, works until t9; never used");
  });

  it("names the export as the server does", () => {
    expect(csvFileName(Date.UTC(2026, 10, 22, 9, 4, 5))).toBe("superbot-access-review-20261122-090405.csv");
  });
});
