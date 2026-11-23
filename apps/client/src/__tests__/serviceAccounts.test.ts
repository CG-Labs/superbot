import {
  canRotate,
  createBody,
  draftChanges,
  draftError,
  draftOf,
  rebaseDraft,
  emptyDraft,
  expiresSoon,
  expiryChoices,
  heldScopes,
  lastUsedLabel,
  roleKey,
  roleLabel,
  scopesLabel,
  toggleScope,
  tokenStatus,
} from "../serviceAccounts";
import type { ServiceAccount, ServiceToken } from "../types";

const DAY = 24 * 60 * 60_000;
const NOW = Date.UTC(2026, 10, 22);

const account = (s: Partial<ServiceAccount> = {}): ServiceAccount => ({
  id: "sa1",
  name: "HR sync",
  description: "",
  role: "readonly",
  status: "active",
  customRole: null,
  team: null,
  teamRole: null,
  owner: { id: "u1", name: "Ada", email: "ada@example.com" },
  ownerActive: true,
  permissions: ["account", "read", "review"],
  teamPermissions: [],
  effective: ["account", "read", "review"],
  tokens: 0,
  lastUsedAt: null,
  createdAt: 0,
  createdBy: "u1",
  updatedAt: 0,
  ...s,
});

const token = (t: Partial<ServiceToken> = {}): ServiceToken => ({
  id: "st1",
  accountId: "sa1",
  name: "CI",
  preview: "sbsa_…abcd",
  scopes: null,
  state: "active",
  createdAt: 0,
  createdBy: "u1",
  expiresAt: NOW + 30 * DAY,
  lastUsedAt: null,
  lastUsedIp: null,
  revokedAt: null,
  revokedBy: null,
  revokedReason: null,
  rotatedTo: null,
  ...t,
});

const SCOPES = ["account", "read", "review", "write", "approve", "users.manage", "bots.manage", "audit.view"];
const ROLES = [
  { id: "r1", base: "member" as const },
  { id: "r2", base: "readonly" as const },
];

describe("service accounts (ADR 0143, 0152)", () => {
  it("offers expiry choices within the server's limit, with its default", () => {
    expect(expiryChoices({ defaultDays: 90, maxDays: 365 }).map((c) => c.value)).toEqual([7, 30, 90, 365]);
    expect(expiryChoices({ defaultDays: 90, maxDays: 365 }).at(-1)?.label).toBe("1 year");
    expect(expiryChoices({ defaultDays: 14, maxDays: 30 }).map((c) => c.value)).toEqual([7, 14, 30]);
  });

  it("reads the role picker's value and label from where the custom role applies", () => {
    expect(roleKey(account())).toBe("readonly");
    expect(roleKey(account({ role: "member", customRole: { id: "r1", name: "Help desk" } }))).toBe("r1");
    expect(roleKey(account({ role: "member", team: { id: "t1", name: "Ops" }, teamRole: { id: "r1", name: "Help desk" } }))).toBe("r1");
    expect(roleLabel(account())).toBe("Read-only");
    expect(roleLabel(account({ role: "member", customRole: { id: "r1", name: "Help desk" } }))).toBe("Help desk");
    expect(roleLabel(account({ role: "member", team: { id: "t1", name: "Ops" } }))).toBe("Member in Ops");
    expect(roleLabel(account({ role: "member", team: { id: "t1", name: "Ops" }, teamRole: { id: "r1", name: "Help desk" } }))).toBe("Member + Help desk in Ops");
  });

  it("refuses drafts the server would, and never offers admin", () => {
    expect(draftError(emptyDraft(), ROLES)).toBe("Give it a name.");
    expect(draftError({ ...emptyDraft(), name: "x".repeat(61) }, ROLES)).toMatch(/60/);
    expect(draftError({ ...emptyDraft(), name: "CI", description: "d".repeat(501) }, ROLES)).toMatch(/500/);
    expect(draftError({ ...emptyDraft(), name: "CI", role: "admin" }, ROLES)).toMatch(/never be an admin/);
    expect(draftError({ ...emptyDraft(), name: "CI", role: "gone" }, ROLES)).toBe("Pick a role.");
    expect(draftError({ ...emptyDraft(), name: "CI", role: "r2", team: "t1" }, ROLES)).toMatch(/read-only/);
    expect(draftError({ ...emptyDraft(), name: "CI", role: "r2" }, ROLES)).toBeNull();
    expect(draftError({ ...emptyDraft(), name: " CI ", role: "r1", team: "t1" }, ROLES)).toBeNull();
  });

  it("creates with a trimmed body and null for across the server", () => {
    expect(createBody({ ...emptyDraft(), name: " CI ", description: " builds ", role: "member" })).toEqual({ name: "CI", description: "builds", role: "member", team: null });
    expect(createBody({ ...emptyDraft(), name: "CI", role: "r1", team: "t1" }).team).toBe("t1");
  });

  it("patches only what changed, and a new role or team together", () => {
    const sa = account({ role: "member", customRole: { id: "r1", name: "Help desk" } });
    expect(draftChanges(sa, draftOf(sa))).toBeNull();
    expect(draftChanges(sa, { ...draftOf(sa), name: " Payroll " })).toEqual({ name: "Payroll" });
    expect(draftChanges(sa, { ...draftOf(sa), team: "t1" })).toEqual({ role: "r1", team: "t1" });
    expect(draftChanges(sa, { ...draftOf(sa), role: "readonly" })).toEqual({ role: "readonly", team: null });
    // The owner as an email in any case, or left blank, changes nothing.
    expect(draftChanges(sa, { ...draftOf(sa), owner: "ADA@example.com" })).toBeNull();
    expect(draftChanges(sa, { ...draftOf(sa), owner: "" })).toBeNull();
    expect(draftChanges(sa, { ...draftOf(sa), owner: "bo@example.com" })).toEqual({ owner: "bo@example.com" });
  });

  it("scopes tokens only to what the account holds, in the server's order", () => {
    const sa = account({ role: "member", permissions: ["account", "read", "review", "write", "approve"], teamPermissions: ["users.manage"] });
    const held = heldScopes({ scopes: SCOPES }, sa);
    expect(held).toEqual(["read", "review", "write", "approve", "users.manage"]);
    expect(toggleScope(held, ["users.manage"], "read")).toEqual(["read", "users.manage"]);
    expect(toggleScope(held, ["read", "users.manage"], "read")).toEqual(["users.manage"]);
    expect(toggleScope(held, ["admin"], "read")).toEqual(["read"]);
    expect(scopesLabel(null)).toBe("Everything the account holds");
    expect(scopesLabel(["account", "read"])).toBe("read");
    expect(scopesLabel(["account"])).toBe("Only who it is");
  });

  it("says what state a token is in and whether it can be rotated", () => {
    expect(tokenStatus(token(), NOW)).toMatch(/^Expires /);
    expect(canRotate(token(), NOW)).toBe(true);
    expect(expiresSoon(token(), NOW)).toBe(false);
    expect(expiresSoon(token({ expiresAt: NOW + 2 * DAY }), NOW)).toBe(true);

    const replaced = token({ rotatedTo: "st2", expiresAt: NOW + 60_000 });
    expect(tokenStatus(replaced, NOW)).toMatch(/^Replaced; works until /);
    expect([canRotate(replaced, NOW), expiresSoon(replaced, NOW)]).toEqual([false, false]);

    expect(tokenStatus(token({ state: "revoked", revokedAt: NOW, revokedReason: "rotated" }), NOW)).toMatch(/^Rotated /);
    expect(tokenStatus(token({ state: "revoked", revokedAt: NOW, revokedReason: "revoked" }), NOW)).toMatch(/^Revoked /);
    expect(canRotate(token({ state: "revoked" }), NOW)).toBe(false);
    expect(tokenStatus(token({ state: "expired", expiresAt: NOW - DAY }), NOW)).toMatch(/^Expired /);
    // Expired since the list loaded.
    expect(canRotate(token({ expiresAt: NOW - 1 }), NOW)).toBe(false);
  });

  it("says when it was last used and from where", () => {
    expect(lastUsedLabel(null)).toBe("Never used");
    expect(lastUsedLabel(NOW, "203.0.113.9")).toMatch(/^Last used .* from 203\.0\.113\.9$/);
    expect(lastUsedLabel(NOW)).not.toMatch(/from/);
  });

  it("rebases a draft so untouched fields take another admin's newer values", () => {
    const was = { name: "HR sync", description: "", role: "member", team: "", owner: "ada@example.com" };
    const now = { ...was, role: "readonly", owner: "bo@example.com" };
    expect(rebaseDraft({ ...was, name: "Payroll" }, was, now)).toEqual({ ...now, name: "Payroll" });
    expect(rebaseDraft({ ...was, role: "r1" }, was, now)).toEqual({ ...now, role: "r1" });
  });
});
