import React from "react";
import { render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { ServiceAccountsAdmin } from "../ServiceAccountsAdmin";
import type { SuperBotApi } from "../../src/api";
import { confirmAsync } from "../../src/dialogs";
import { copyText } from "../../src/clipboard";
import type { MintedServiceToken, ServiceAccount, ServiceAccountsView, ServiceToken, Team } from "../../src/types";

jest.mock("../../src/dialogs", () => ({ confirmAsync: jest.fn(async () => true) }));
jest.mock("../../src/clipboard", () => ({ COPY_LABEL: "Copy", copyText: jest.fn(async () => true) }));

const DAY = 24 * 60 * 60_000;
const SECRET = "sbsa_" + "f".repeat(64);
const ROTATED = "sbsa_" + "e".repeat(64);

const TOKEN: ServiceToken = {
  id: "st1",
  accountId: "sa1",
  name: "CI",
  preview: "sbsa_…ffff",
  scopes: ["read"],
  state: "active",
  createdAt: 0,
  createdBy: "me",
  expiresAt: Date.now() + 30 * DAY,
  lastUsedAt: Date.now() - 60_000,
  lastUsedIp: "203.0.113.9",
  revokedAt: null,
  revokedBy: null,
  revokedReason: null,
  rotatedTo: null,
};

const SA: ServiceAccount = {
  id: "sa1",
  name: "HR sync",
  description: "",
  role: "member",
  status: "active",
  customRole: null,
  team: null,
  teamRole: null,
  owner: { id: "me", name: "Me", email: "me@example.com" },
  ownerActive: true,
  permissions: ["account", "read", "review", "write", "approve"],
  teamPermissions: [],
  effective: ["account", "read", "review", "write", "approve"],
  tokens: 1,
  lastUsedAt: TOKEN.lastUsedAt,
  createdAt: 0,
  createdBy: "me",
  updatedAt: 0,
};

const VIEW: ServiceAccountsView = { serviceAccounts: [SA], scopes: ["account", "read", "review", "write", "approve", "users.manage"], defaultDays: 90, maxDays: 365 };
const TEAM: Team = { id: "t1", name: "Ops", machines: false, createdAt: 0, members: [] };

const minted = (token: string, info: Partial<ServiceToken> = {}, replaced?: MintedServiceToken["replaced"]): MintedServiceToken => ({
  token,
  tokenInfo: { ...TOKEN, id: "st2", scopes: null, lastUsedAt: null, lastUsedIp: null, ...info },
  serviceAccount: { id: "sa1", name: "HR sync" },
  replaced,
});

function mockApi(view: ServiceAccountsView = VIEW) {
  return {
    serviceAccounts: jest.fn(async () => view),
    serviceAccount: jest.fn(async (id: string) => ({ ...(view.serviceAccounts.find((s) => s.id === id) ?? SA), tokenList: [TOKEN] })),
    roles: jest.fn(async () => ({ permissions: [], builtIn: [], roles: [{ id: "r1", name: "Help desk", description: "", base: "member", builtIn: false, permissions: ["users.manage"], unknown: [], effective: [], users: 0, teamMembers: 0, createdAt: 0, createdBy: null, updatedAt: 0 }] })),
    teams: jest.fn(async () => [TEAM]),
    createServiceAccount: jest.fn(async () => SA),
    updateServiceAccount: jest.fn(async () => SA),
    deleteServiceAccount: jest.fn(async () => ({ tokensRevoked: 1 })),
    createServiceToken: jest.fn(async () => minted(SECRET)),
    rotateServiceToken: jest.fn(async () => minted(ROTATED, {}, { id: "st1", endsAt: Date.now() + 60 * 60_000 })),
    revokeServiceToken: jest.fn(async () => {}),
  };
}

const show = (api: ReturnType<typeof mockApi>) => render(<ServiceAccountsAdmin api={api as unknown as SuperBotApi} onBack={jest.fn()} />);

async function open(api: ReturnType<typeof mockApi>, u: ReturnType<typeof userEvent.setup>) {
  await show(api);
  await u.press(await screen.findByLabelText("Service account HR sync"));
  await screen.findByLabelText("Revoke CI");
}

describe("ServiceAccountsAdmin (ADR 0143, 0152)", () => {
  beforeEach(() => jest.clearAllMocks());

  it("lists accounts with their role, live tokens and last use", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [SA, { ...SA, id: "sa2", name: "Export", role: "readonly", status: "disabled", ownerActive: false, tokens: 0, lastUsedAt: null }] });
    await show(api);
    expect(await screen.findByLabelText("Service account HR sync")).toBeTruthy();
    expect(screen.getByText(/Member · 1 live token · last used/)).toBeTruthy();
    expect(screen.getByText(/Read-only · 0 live tokens · never used/)).toBeTruthy();
    expect(screen.getByText(" · disabled")).toBeTruthy();
    expect(screen.getByText(" · owner inactive")).toBeTruthy();
  });

  it("makes an account with its first token, and shows the secret once", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New service account"));
    await u.type(screen.getByLabelText("Service account name"), "HR sync");
    await u.press(screen.getByRole("radio", { name: "Help desk" }));
    await u.press(screen.getByRole("radio", { name: "Ops" }));
    await u.press(screen.getByRole("radio", { name: "30 days" }));
    await u.press(screen.getByLabelText("Create service account"));

    await waitFor(() => expect(api.createServiceAccount).toHaveBeenCalledWith({ name: "HR sync", description: "", role: "r1", team: "t1" }));
    expect(api.createServiceToken).toHaveBeenCalledWith("sa1", { expiresInDays: 30 });
    expect(await screen.findByTestId("token-value")).toHaveTextContent(SECRET);
    await u.press(screen.getByLabelText("Copy token"));
    expect(copyText).toHaveBeenCalledWith(SECRET);
    expect(await screen.findByText("Copied")).toBeTruthy();

    // Done forgets it; nothing can show it again.
    await u.press(screen.getByLabelText("Done"));
    expect(screen.queryByTestId("token-reveal")).toBeNull();
    expect(screen.queryByText(SECRET)).toBeNull();
  });

  it("can make an account without a token", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New service account"));
    await u.type(screen.getByLabelText("Service account name"), "Export");
    await u.press(screen.getByRole("checkbox", { name: "Make a token now" }));
    await u.press(screen.getByLabelText("Create service account"));
    await waitFor(() => expect(api.createServiceAccount).toHaveBeenCalledWith({ name: "Export", description: "", role: "readonly", team: null }));
    expect(api.createServiceToken).not.toHaveBeenCalled();
  });

  it("issues a scoped token, and forgets its secret when another account is picked", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [SA, { ...SA, id: "sa2", name: "Export" }] });
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.getByText(/from 203\.0\.113\.9/)).toBeTruthy();
    // Only what it holds; never users.manage, which a member doesn't hold.
    expect(screen.queryByRole("checkbox", { name: "Scope users.manage" })).toBeNull();
    await u.type(screen.getByLabelText("Token name"), "Nightly");
    await u.press(screen.getByRole("checkbox", { name: "Scope write" }));
    await u.press(screen.getByRole("checkbox", { name: "Scope read" }));
    await u.press(screen.getByRole("radio", { name: "7 days" }));
    await u.press(screen.getByLabelText("Make token"));
    await waitFor(() => expect(api.createServiceToken).toHaveBeenCalledWith("sa1", { name: "Nightly", scopes: ["read", "write"], expiresInDays: 7 }));
    expect(await screen.findByTestId("token-value")).toHaveTextContent(SECRET);

    await u.press(screen.getByLabelText("Service account Export"));
    await waitFor(() => expect(screen.queryByTestId("token-reveal")).toBeNull());
  });

  it("rotates with an overlap, and revokes after asking", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Rotate CI"));
    await u.press(screen.getByRole("radio", { name: "Keep it 1 hour" }));
    await u.press(screen.getByLabelText("Confirm rotate CI"));
    await waitFor(() => expect(api.rotateServiceToken).toHaveBeenCalledWith("sa1", "st1", { expiresInDays: 90, keepOldMinutes: 60 }));
    expect(await screen.findByTestId("token-value")).toHaveTextContent(ROTATED);
    expect(screen.getByText(/The old token stops /)).toBeTruthy();

    await u.press(screen.getByLabelText("Revoke CI"));
    expect(confirmAsync).toHaveBeenCalledWith("Revoke CI?", expect.any(String), "Revoke");
    await waitFor(() => expect(api.revokeServiceToken).toHaveBeenCalledWith("sa1", "st1"));
  });

  it("doesn't revoke when the admin says no", async () => {
    (confirmAsync as jest.Mock).mockResolvedValueOnce(false);
    const api = mockApi();
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Revoke CI"));
    expect(api.revokeServiceToken).not.toHaveBeenCalled();
  });

  it("disables, enables and deletes", async () => {
    const api = mockApi();
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Disable"));
    await waitFor(() => expect(api.updateServiceAccount).toHaveBeenCalledWith("sa1", { status: "disabled" }));
    await u.press(screen.getByLabelText("Delete"));
    await waitFor(() => expect(api.deleteServiceAccount).toHaveBeenCalledWith("sa1"));
    expect(confirmAsync).toHaveBeenLastCalledWith("Delete HR sync?", expect.stringMatching(/revoked/), "Delete");
  });

  it("offers no tokens on a disabled account, only Enable", async () => {
    const off = { ...SA, status: "disabled" as const };
    const api = mockApi({ ...VIEW, serviceAccounts: [off] });
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.queryByLabelText("Make token")).toBeNull();
    expect(screen.getByLabelText("Rotate CI")).toBeDisabled();
    await u.press(screen.getByLabelText("Enable"));
    await waitFor(() => expect(api.updateServiceAccount).toHaveBeenCalledWith("sa1", { status: "active" }));
  });

  it("changes the role and owner with only what changed, and shows the server's refusal", async () => {
    const api = mockApi();
    api.updateServiceAccount.mockRejectedValueOnce(new Error("A service account can't hold more than its owner. Bo doesn't hold: users.manage."));
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.getByLabelText("Save")).toBeDisabled();
    await u.press(screen.getAllByRole("radio", { name: "Help desk" })[0]);
    await u.clear(screen.getByLabelText("Owner's email or id"));
    await u.type(screen.getByLabelText("Owner's email or id"), "bo@example.com");
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateServiceAccount).toHaveBeenCalledWith("sa1", { role: "r1", team: null, owner: "bo@example.com" }));
    expect(await screen.findByText(/can't hold more than its owner/)).toBeTruthy();
  });

  it("warns when the owner can no longer lend access", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [{ ...SA, ownerActive: false, effective: [] }] });
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.getByText(/Its owner is disabled or gone/)).toBeTruthy();
  });
});
