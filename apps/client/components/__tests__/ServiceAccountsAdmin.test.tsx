import React from "react";
import { act, render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { ServiceAccountsAdmin } from "../ServiceAccountsAdmin";
import type { SuperBotApi } from "../../src/api";
import { confirmAsync } from "../../src/dialogs";
import { copyText } from "../../src/clipboard";
import type { MintedServiceToken, ServiceAccount, ServiceAccountChoices, ServiceAccountsView, ServiceToken, Team } from "../../src/types";

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
    keepBot: jest.fn(async () => ({})),
    keepBots: jest.fn(async () => ({})),
    releaseKeptBot: jest.fn(async () => ({})),
  };
}

const show = (api: ReturnType<typeof mockApi>, admin = true) => render(<ServiceAccountsAdmin api={api as unknown as SuperBotApi} onBack={jest.fn()} admin={admin} />);

const CHOICES: ServiceAccountChoices = {
  roles: [
    { id: "readonly", name: "Read-only", base: "readonly", builtIn: true, permissions: [] },
    { id: "member", name: "Member", base: "member", builtIn: true, permissions: [] },
    { id: "r1", name: "Help desk", base: "member", builtIn: false, permissions: ["users.manage"] },
  ],
  server: ["readonly", "member", "r1"],
  teams: [{ id: "t1", name: "Ops", roles: ["readonly", "member"] }],
};
const OWN: ServiceAccountsView = { ...VIEW, view: "own", choices: CHOICES };

async function open(api: ReturnType<typeof mockApi>, u: ReturnType<typeof userEvent.setup>) {
  await show(api);
  await u.press(await screen.findByLabelText("Service account HR sync"));
  await screen.findByLabelText("Revoke CI");
}

// The first render loads and transforms React Native's lazy modules, which on a cold, busy CI
// runner takes longer than a test's 5 s; pay for it once here, with the list and a detail open.
beforeAll(async () => {
  const { unmount } = await show(mockApi());
  await userEvent.setup().press(await screen.findByLabelText("Service account HR sync"));
  await screen.findByLabelText("Revoke CI");
  await unmount();
}, 60_000);

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

  it("says how many Bots an account keeps (ADR 0222)", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [{ ...SA, keptBots: 2 }, { ...SA, id: "sa2", name: "Export", keptBots: 1 }] });
    await show(api);
    expect(await screen.findByText(/Member · 1 live token · keeps 2 Bots · last used/)).toBeTruthy();
    expect(screen.getByText(/Member · 1 live token · keeps 1 Bot · last used/)).toBeTruthy();
  });

  it("hands it one of its owner's Bots, and takes one back, after asking (ADR 0229)", async () => {
    const api = mockApi({ ...VIEW, maxKeptBots: 20 });
    api.serviceAccount.mockImplementation(async () => ({
      ...SA,
      tokenList: [TOKEN],
      keptBotList: [{ id: "b1", name: "Ledger", visibility: "private" as const }],
      keepable: [{ id: "b2", name: "Notes", visibility: "private" as const, keptBy: { id: "sa9", name: "Nightly" } }],
    }));
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.getByText("Bots it keeps (1 of 20)")).toBeTruthy();

    await u.press(screen.getByLabelText("Take Ledger back"));
    await waitFor(() => expect(api.releaseKeptBot).toHaveBeenCalledWith("b1"));
    expect(confirmAsync).toHaveBeenLastCalledWith("Take Ledger back from HR sync?", expect.stringMatching(/stay with its owner/), "Take it back");

    expect(screen.getByLabelText("Hand it over")).toBeDisabled();
    await u.press(screen.getByText("Notes (from Nightly)"));
    await u.press(screen.getByLabelText("Hand it over"));
    await waitFor(() => expect(api.keepBot).toHaveBeenCalledWith("b2", "sa1"));
    expect(confirmAsync).toHaveBeenLastCalledWith("Let HR sync keep Notes?", expect.stringMatching(/owner's keys and memory.*Nightly stops keeping it/), "Hand it over");
  });

  it("hands it several Bots in one request, no more than it has room for (ADR 0324)", async () => {
    const api = mockApi({ ...VIEW, maxKeptBots: 3 });
    api.serviceAccount.mockImplementation(async () => ({
      ...SA,
      tokenList: [TOKEN],
      keptBotList: [{ id: "b1", name: "Ledger", visibility: "private" as const }],
      keepable: [
        { id: "b2", name: "Notes", visibility: "private" as const, keptBy: { id: "sa9", name: "Nightly" } },
        { id: "b3", name: "Wiki", visibility: "shared" as const, keptBy: null },
        { id: "b4", name: "Extra", visibility: "private" as const, keptBy: null },
      ],
    }));
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.getByText(/Hand it up to 2 of/)).toBeTruthy();

    await u.press(screen.getByLabelText("Hand over Notes"));
    await u.press(screen.getByLabelText("Hand over Wiki"));
    expect(screen.getByLabelText("Hand over Extra")).toBeDisabled();
    await u.press(screen.getByLabelText("Hand over 2 Bots"));
    await waitFor(() => expect(api.keepBots).toHaveBeenCalledWith("sa1", ["b2", "b3"]));
    expect(api.keepBot).not.toHaveBeenCalled();
    expect(confirmAsync).toHaveBeenLastCalledWith("Let HR sync keep 2 Bots?", expect.stringMatching(/^Notes, Wiki\..*Nightly stops keeping Notes\.$/), "Hand over 2 Bots");
  });

  it("forgets picks a reload no longer offers, so they don't hold up others", async () => {
    const api = mockApi({ ...VIEW, maxKeptBots: 3 });
    const bot = (id: string, name: string) => ({ id, name, visibility: "private" as const, keptBy: null });
    let state = { keptBotList: [bot("b1", "Ledger")], keepable: [bot("b2", "Notes"), bot("b3", "Wiki"), bot("b4", "Extra")] };
    api.serviceAccount.mockImplementation(async () => ({ ...SA, tokenList: [TOKEN], ...state }));
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Hand over Notes"));
    await u.press(screen.getByLabelText("Hand over Wiki"));
    expect(screen.getByLabelText("Hand over Extra")).toBeDisabled();

    // Still room for two, but Notes and Wiki are no longer offered.
    state = { keptBotList: [bot("b5", "Other")], keepable: [bot("b4", "Extra"), bot("b1", "Ledger")] };
    await u.press(screen.getByLabelText("Take Ledger back"));
    await screen.findByLabelText("Take Other back");
    expect(screen.getByLabelText("Hand over Extra")).toBeEnabled();
    expect(screen.getByLabelText("Hand it over")).toBeDisabled();
    await u.press(screen.getByLabelText("Hand over Extra"));
    await u.press(screen.getByLabelText("Hand it over"));
    await waitFor(() => expect(api.keepBot).toHaveBeenCalledWith("b4", "sa1"));
    expect(api.keepBots).not.toHaveBeenCalled();
  });

  it("doesn't take a Bot back when they say no, and offers none past the limit", async () => {
    const api = mockApi({ ...VIEW, maxKeptBots: 1 });
    api.serviceAccount.mockImplementation(async () => ({
      ...SA,
      tokenList: [TOKEN],
      keptBotList: [{ id: "b1", name: "Ledger", visibility: "private" as const }],
      keepable: [{ id: "b2", name: "Notes", visibility: "private" as const, keptBy: null }],
    }));
    (confirmAsync as jest.Mock).mockResolvedValueOnce(false);
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Take Ledger back"));
    await waitFor(() => expect(confirmAsync).toHaveBeenCalled());
    expect(api.releaseKeptBot).not.toHaveBeenCalled();
    expect(screen.queryByText("Notes")).toBeNull();
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

  it("still shows the first token when the list doesn't reload", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [] });
    api.serviceAccounts.mockResolvedValueOnce({ ...VIEW, serviceAccounts: [] }).mockRejectedValueOnce(new Error("offline"));
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("New service account"));
    await u.type(screen.getByLabelText("Service account name"), "HR sync");
    await u.press(screen.getByLabelText("Create service account"));
    expect(await screen.findByTestId("token-value")).toHaveTextContent(SECRET);
    expect(screen.getByLabelText("Service account HR sync")).toBeTruthy();
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

  it("won't switch accounts while a rotate is pending, so its new secret is still shown", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [SA, { ...SA, id: "sa2", name: "Export" }] });
    let finish: (m: MintedServiceToken) => void = () => {};
    api.rotateServiceToken.mockImplementationOnce(() => new Promise<MintedServiceToken>((resolve) => (finish = resolve)));
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Rotate CI"));
    await u.press(screen.getByLabelText("Confirm rotate CI"));
    await waitFor(() => expect(screen.getByLabelText("Service account Export")).toBeDisabled());
    expect(screen.getByLabelText("New service account")).toBeDisabled();
    expect(screen.getByLabelText("Back to Bots")).toBeDisabled();
    await u.press(screen.getByLabelText("Service account Export"));
    expect(api.serviceAccount).not.toHaveBeenCalledWith("sa2");

    finish(minted(ROTATED));
    expect(await screen.findByTestId("token-value")).toHaveTextContent(ROTATED);
    await waitFor(() => expect(screen.getByLabelText("Service account Export")).not.toBeDisabled());
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

  it("doesn't undo another admin's change when saving from a stale list", async () => {
    const api = mockApi();
    api.serviceAccount.mockResolvedValue({ ...SA, role: "readonly", tokenList: [TOKEN] });
    const u = userEvent.setup();
    await open(api, u);
    await u.clear(screen.getByLabelText("Service account name"));
    await u.type(screen.getByLabelText("Service account name"), "Payroll");
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateServiceAccount).toHaveBeenCalledWith("sa1", { name: "Payroll" }));
  });

  it("warns when the owner can no longer lend access", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [{ ...SA, ownerActive: false, effective: [] }] });
    const u = userEvent.setup();
    await open(api, u);
    expect(screen.getByText(/Its owner is disabled or gone/)).toBeTruthy();
  });
});

describe("ServiceAccountsAdmin: loading, empty and error states (ADR 0345)", () => {
  beforeEach(() => jest.clearAllMocks());

  it("shows a skeleton while the list loads, then an error that tries again", async () => {
    const api = mockApi();
    let fail: (e: Error) => void = () => {};
    api.serviceAccounts.mockImplementationOnce(() => new Promise((_, reject) => (fail = reject)));
    await show(api);
    expect(screen.getByRole("progressbar", { name: "Loading service accounts" })).toBeOnTheScreen();
    await act(async () => fail(new TypeError("Failed to fetch")));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load service accountsCan't reach the server. Check your connection and try again.");
    await userEvent.setup().press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByLabelText("Service account HR sync")).toBeOnTheScreen();
    expect(api.serviceAccounts).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says when there are no service accounts yet", async () => {
    await show(mockApi({ ...VIEW, serviceAccounts: [] }));
    expect(await screen.findByRole("heading", { name: "No service accounts yet" })).toBeOnTheScreen();
  });

  it("shows a skeleton while its tokens load, and a retry when they don't", async () => {
    const api = mockApi();
    let fail: (e: Error) => void = () => {};
    api.serviceAccount.mockImplementationOnce(() => new Promise((_, reject) => (fail = reject)));
    const u = userEvent.setup();
    await show(api);
    await u.press(await screen.findByLabelText("Service account HR sync"));
    expect(screen.getByRole("progressbar", { name: "Loading tokens" })).toBeOnTheScreen();
    await act(async () => fail(new Error("Server error")));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load its tokens. Server error");
    await u.press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByLabelText("Revoke CI")).toBeOnTheScreen();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says when it has no tokens, titles its sections and marks the picked account", async () => {
    const api = mockApi({ ...VIEW, serviceAccounts: [{ ...SA, tokens: 0 }] });
    api.serviceAccount.mockResolvedValue({ ...SA, tokens: 0, tokenList: [] });
    const u = userEvent.setup();
    await show(api);
    expect(await screen.findByRole("button", { name: "Service account HR sync" })).not.toBeSelected();
    await u.press(screen.getByRole("button", { name: "Service account HR sync" }));
    expect(await screen.findByRole("heading", { name: "No tokens yet" })).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Service account HR sync" })).toBeSelected();
    expect(screen.getByRole("heading", { name: "HR sync" })).toBeOnTheScreen();
    expect(screen.getByRole("heading", { name: "Tokens (0 live)" })).toBeOnTheScreen();
    expect(screen.getByRole("heading", { name: "New token" })).toBeOnTheScreen();
  });

  it("shows a failed revoke as an alert in plain words", async () => {
    const api = mockApi();
    api.revokeServiceToken.mockRejectedValueOnce(new TypeError("Network request failed"));
    const u = userEvent.setup();
    await open(api, u);
    await u.press(screen.getByLabelText("Revoke CI"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Can't reach the server. Check your connection and try again.");
  });
});

describe("ServiceAccountsAdmin for a delegate (ADR 0182)", () => {
  beforeEach(() => jest.clearAllMocks());

  it("shows their own, and offers only what the server says they may give", async () => {
    const api = mockApi(OWN);
    const u = userEvent.setup();
    await show(api, false);
    expect(await screen.findByText("Your service accounts")).toBeTruthy();
    expect(api.roles).not.toHaveBeenCalled();
    expect(api.teams).not.toHaveBeenCalled();

    await u.press(screen.getByLabelText("New service account"));
    await u.type(screen.getByLabelText("Service account name"), "Nightly");
    expect(screen.getByRole("radio", { name: "Help desk" })).toBeTruthy();
    // In Ops she may give only the built-in roles.
    await u.press(screen.getByRole("radio", { name: "Ops" }));
    expect(screen.queryByRole("radio", { name: "Help desk" })).toBeNull();
    await u.press(screen.getByRole("radio", { name: "Member" }));
    await u.press(screen.getByLabelText("Create service account"));
    await waitFor(() => expect(api.createServiceAccount).toHaveBeenCalledWith({ name: "Nightly", description: "", role: "member", team: "t1" }));
  });

  it("can't change the owner, and keeps a role no longer offered so the account can still be renamed", async () => {
    const old = { ...SA, customRole: { id: "r9", name: "Old role" } };
    const api = mockApi({ ...OWN, serviceAccounts: [old] });
    const u = userEvent.setup();
    await show(api, false);
    await u.press(await screen.findByLabelText("Service account HR sync"));
    await screen.findByLabelText("Revoke CI");
    expect(screen.queryByLabelText("Owner's email or id")).toBeNull();
    expect(screen.getByRole("radio", { name: "Old role" })).toBeTruthy();
    await u.clear(screen.getByLabelText("Service account name"));
    await u.type(screen.getByLabelText("Service account name"), "Payroll");
    await u.press(screen.getByLabelText("Save"));
    await waitFor(() => expect(api.updateServiceAccount).toHaveBeenCalledWith("sa1", { name: "Payroll" }));
  });

  it("says when its owner isn't on its team", async () => {
    const off = { ...SA, team: { id: "t1", name: "Ops" }, ownerOnTeam: false };
    const api = mockApi({ ...OWN, serviceAccounts: [off] });
    const u = userEvent.setup();
    await show(api, false);
    expect(await screen.findByText(" · owner off its team")).toBeTruthy();
    await u.press(screen.getByLabelText("Service account HR sync"));
    expect(await screen.findByText(/isn't on Ops, so it acts in no team/)).toBeTruthy();
  });

  it("gives an admin the server's choices too, without reading every role", async () => {
    const api = mockApi({ ...VIEW, view: "all", choices: CHOICES });
    await show(api);
    expect(await screen.findByText("Service accounts")).toBeTruthy();
    expect(api.roles).not.toHaveBeenCalled();
  });
});

describe("ServiceAccountsAdmin for an owner who manages none (ADR 0239)", () => {
  beforeEach(() => jest.clearAllMocks());
  const OWNED: ServiceAccountsView = { ...VIEW, view: "own", manage: false, choices: null };

  it("shows theirs and its tokens, with revoke and disable but nothing that makes or changes one", async () => {
    const api = mockApi(OWNED);
    const u = userEvent.setup();
    await show(api, false);
    expect(await screen.findByText("Your service accounts")).toBeTruthy();
    expect(screen.queryByLabelText("New service account")).toBeNull();
    await u.press(screen.getByLabelText("Service account HR sync"));
    await screen.findByLabelText("Revoke CI");
    expect(screen.getByText(/acts with your access/)).toBeTruthy();
    for (const label of ["Rotate CI", "Make token", "Service account name", "Save", "Delete", "Enable"]) expect(screen.queryByLabelText(label)).toBeNull();
    expect(api.roles).not.toHaveBeenCalled();
    expect(api.teams).not.toHaveBeenCalled();

    await u.press(screen.getByLabelText("Revoke CI"));
    await waitFor(() => expect(api.revokeServiceToken).toHaveBeenCalledWith("sa1", "st1"));
    await u.press(screen.getByLabelText("Disable"));
    await waitFor(() => expect(api.updateServiceAccount).toHaveBeenCalledWith("sa1", { status: "disabled" }));
  });

  it("leaves enabling a disabled one to an admin", async () => {
    const api = mockApi({ ...OWNED, serviceAccounts: [{ ...SA, status: "disabled" }] });
    const u = userEvent.setup();
    await show(api, false);
    await u.press(await screen.findByLabelText("Service account HR sync"));
    expect(await screen.findByText(/Ask an admin to enable it again/)).toBeTruthy();
    expect(screen.queryByLabelText("Enable")).toBeNull();
    expect(screen.queryByLabelText("Disable")).toBeNull();
  });

  it("treats a server from before it as managing, since only managers got a list", async () => {
    const api = mockApi({ ...OWN, manage: undefined });
    await show(api, false);
    expect(await screen.findByLabelText("New service account")).toBeTruthy();
  });
});
