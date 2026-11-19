import React from "react";
import { act, render, screen, userEvent, within } from "@testing-library/react-native";
import { UsersAdmin, matchesUser } from "../UsersAdmin";
import type { SuperBotApi } from "../../src/api";
import { fetchSsoProviders } from "../../src/sso";
import type { AdminUser } from "../../src/types";

jest.mock("../BotAvatar", () => ({ BotAvatar: () => null }));
jest.mock("../../src/sso", () => ({
  fetchSsoProviders: jest.fn(async () => [{ id: "github", label: "GitHub", type: "github" }]),
}));
const mockConfirm = jest.fn(async () => true);
jest.mock("../../src/dialogs", () => ({ confirmAsync: (...a: unknown[]) => mockConfirm(...(a as [])) }));

const BASE = "https://bots.example.com";
const CODE = "sbc_" + "ef".repeat(32);

const owner: AdminUser = {
  id: "operator",
  email: "owner@example.com",
  name: "Owner",
  role: "admin",
  status: "active",
  breakGlass: true,
  createdAt: 1,
  updatedAt: 1,
  lastLoginAt: Date.now() - 5 * 60_000,
  lastLogin: { at: Date.now() - 5 * 60_000, authMethod: "sso", idpProvider: "work", idp: "entra" },
  identities: [],
  pendingCodes: null,
};
const alex: AdminUser = {
  ...owner,
  id: "u1",
  email: "alex@example.com",
  name: "Alex",
  role: "member",
  breakGlass: false,
  lastLoginAt: null,
  identities: [{ id: "i1", provider: "github", subject: "42", email: "alex@example.com", createdAt: 1 }],
  pendingCodes: { count: 1, expiresAt: Date.now() + 3600_000 },
};

function fakeApi(list: AdminUser[]) {
  const users = list.map((u) => ({ ...u }));
  return {
    baseUrl: BASE,
    users: jest.fn(async () => users.map((u) => ({ ...u }))),
    createUser: jest.fn(async (b: { email: string; name?: string; role: AdminUser["role"] }) => {
      const u: AdminUser = { ...alex, id: "u2", email: b.email, name: b.name ?? "x", role: b.role, identities: [], pendingCodes: null };
      users.push(u);
      return u;
    }),
    patchUser: jest.fn(async (id: string, b: Partial<AdminUser>) => {
      const u = users.find((x) => x.id === id)!;
      Object.assign(u, b);
      return u;
    }),
    createLoginCode: jest.fn(async () => ({ code: CODE, expiresAt: Date.now() + 24 * 3600_000 })),
    userSessions: jest.fn(async () => [{ id: "s1", kind: "token", method: "code", label: "Phone", createdAt: 1, lastSeenAt: Date.now(), endsAt: 2 }]),
    revokeUserSessions: jest.fn(async () => ({ revoked: 1 })),
    linkIdentity: jest.fn(async () => ({})),
    unlinkIdentity: jest.fn(async () => {}),
    userBots: jest.fn(async () => ({
      active: true,
      bots: [{ bot: { id: "b1", name: "Scout", color: "#fff", shape: "waddle" }, owner: { id: "operator", name: "Owner" }, visibility: "private", access: "view", grant: "viewer" }],
    })),
  };
}

async function open(list: AdminUser[]) {
  const api = fakeApi(list);
  const user = userEvent.setup();
  await render(<UsersAdmin api={api as unknown as SuperBotApi} meId="operator" onBack={jest.fn()} />);
  await screen.findByLabelText("User Alex");
  return { api, user };
}

beforeEach(() => mockConfirm.mockClear());

describe("UsersAdmin", () => {
  it("lists people with role, status, linked sign-ins, waiting codes, and last sign-in", async () => {
    await open([owner, alex]);
    const row = within(screen.getByLabelText("User Alex"));
    expect(row.getByText("alex@example.com")).toBeOnTheScreen();
    expect(row.getByText("Member")).toBeOnTheScreen();
    expect(row.getByText("GitHub")).toBeOnTheScreen();
    expect(row.getByText("Code waiting")).toBeOnTheScreen();
    expect(row.getByText("Never")).toBeOnTheScreen();
    expect(within(screen.getByLabelText("User Owner")).getByText("5 min ago")).toBeOnTheScreen();
    expect(within(screen.getByLabelText("User Owner")).getByText("with SSO (work)")).toBeOnTheScreen();
  });

  it("adds a user with a code and shows the code and invite once", async () => {
    const { api, user } = await open([owner, alex]);
    await user.press(screen.getByText("Add user"));
    await user.type(screen.getByLabelText("Email"), "sam@example.com");
    await user.type(screen.getByLabelText("Name"), "Sam");
    await user.press(screen.getByRole("radio", { name: "Read-only" }));
    await user.press(screen.getByRole("radio", { name: "7 days" }));
    await user.press(screen.getAllByText("Add user").at(-1)!);

    expect(api.createUser).toHaveBeenCalledWith({ email: "sam@example.com", name: "Sam", role: "readonly" });
    expect(api.createLoginCode).toHaveBeenCalledWith("u2", 10080);
    const reveal = within(await screen.findByTestId("code-reveal"));
    expect(reveal.getByTestId("code-value")).toHaveTextContent(CODE);
    expect(reveal.getByText(/shown once/)).toBeOnTheScreen();
    expect(reveal.getByText(`${BASE}/app/#code=${CODE}`, { exact: false })).toBeOnTheScreen();

    expect(screen.queryByText(/^Scout/)).not.toBeOnTheScreen();
    await user.press(reveal.getByText("Done"));
    expect(screen.queryByTestId("code-reveal")).not.toBeOnTheScreen();
    expect(screen.queryByText(CODE)).not.toBeOnTheScreen();
    expect(await screen.findByText(/^Scout/)).toBeOnTheScreen();
  });

  it("closing the invite with Back opens the new user once, not on a later Cancel", async () => {
    const { user } = await open([owner, alex]);
    await user.press(screen.getByText("Add user"));
    await user.type(screen.getByLabelText("Email"), "sam@example.com");
    await user.press(screen.getAllByText("Add user").at(-1)!);
    await screen.findByTestId("code-reveal");
    await act(async () => screen.getByTestId("invite-modal").props.onRequestClose());
    expect(await screen.findByText(/^Scout/)).toBeOnTheScreen();
    await user.press(screen.getByLabelText("User Owner"));
    await user.press(screen.getByText("Add user"));
    await user.press(screen.getByText("Cancel"));
    expect(screen.getByText("Owner (break-glass) · ", { exact: false })).toBeOnTheScreen();
  });

  it("changes a role, regenerates a code, signs out, and shows Bot access", async () => {
    const { api, user } = await open([owner, alex]);
    await user.press(screen.getByLabelText("User Alex"));
    await screen.findByText(/^Scout/);
    expect(screen.getByText("Can view")).toBeOnTheScreen();

    await user.press(screen.getByRole("radio", { name: "Admin" }));
    expect(api.patchUser).toHaveBeenCalledWith("u1", { role: "admin" });

    await user.press(screen.getByRole("radio", { name: "1 hour" }));
    await user.press(screen.getByText("New code"));
    expect(mockConfirm).toHaveBeenCalled();
    expect(api.createLoginCode).toHaveBeenCalledWith("u1", 60, true);
    expect(await screen.findByTestId("code-reveal")).toBeOnTheScreen();

    await user.press(screen.getByText("Sign out everywhere"));
    expect(api.revokeUserSessions).toHaveBeenCalledWith("u1");
    expect(screen.queryByTestId("code-reveal")).toBeNull();

    await user.press(screen.getByText("Disable"));
    expect(api.patchUser).toHaveBeenCalledWith("u1", { status: "disabled" });

    await user.press(screen.getByText("Unlink"));
    expect(api.unlinkIdentity).toHaveBeenCalledWith("u1", "i1");
  });

  it("shows a failed load with a retry, and still offers sign out", async () => {
    const { api, user } = await open([owner, alex]);
    api.userSessions.mockRejectedValueOnce(new Error("Server unreachable"));
    api.userBots.mockRejectedValueOnce(new Error("Server unreachable"));
    await user.press(screen.getByLabelText("User Alex"));
    expect(await screen.findAllByText("Server unreachable")).toHaveLength(2);
    expect(screen.getByText("Sign out everywhere")).toBeOnTheScreen();
    await user.press(screen.getAllByText("Retry")[0]);
    expect(await screen.findByText(/^Scout/)).toBeOnTheScreen();
    expect(screen.queryByText("Server unreachable")).toBeNull();
  });

  it("links an SSO account by its id at the provider", async () => {
    const { api, user } = await open([owner, alex]);
    await user.press(screen.getByLabelText("User Alex"));
    await user.type(await screen.findByLabelText("Subject"), "4242");
    await user.press(screen.getByText("Link"));
    expect(api.linkIdentity).toHaveBeenCalledWith("u1", { provider: "github", subject: "4242", tenant: undefined });
  });

  it("links with the first provider when providers arrive after the user opens", async () => {
    let arrive: (p: unknown) => void = () => {};
    jest.mocked(fetchSsoProviders).mockImplementationOnce(() => new Promise((r) => (arrive = r as typeof arrive)));
    const { api, user } = await open([owner, alex]);
    await user.press(screen.getByLabelText("User Alex"));
    await act(async () => arrive([{ id: "work", label: "Work", type: "entra" }]));
    await user.type(await screen.findByLabelText("Subject"), "oid-1");
    expect(screen.getByLabelText("Tenant")).toBeOnTheScreen();
    await user.press(screen.getByText("Link"));
    expect(api.linkIdentity).toHaveBeenCalledWith("u1", { provider: "work", subject: "oid-1", tenant: undefined });
  });

  it("sends a tenant only to Entra, even after switching away from it", async () => {
    jest.mocked(fetchSsoProviders).mockResolvedValueOnce([
      { id: "work", label: "Work", type: "entra" },
      { id: "github", label: "GitHub", type: "github" },
    ]);
    const { api, user } = await open([owner, alex]);
    await user.press(screen.getByLabelText("User Alex"));
    await user.type(await screen.findByLabelText("Tenant"), "tid-1");
    await user.press(screen.getByRole("radio", { name: "GitHub" }));
    await user.type(screen.getByLabelText("Subject"), "4242");
    await user.press(screen.getByText("Link"));
    expect(api.linkIdentity).toHaveBeenCalledWith("u1", { provider: "github", subject: "4242", tenant: undefined });
  });

  it("shows SAML links by their provider and links one by its NameID", async () => {
    jest.mocked(fetchSsoProviders).mockResolvedValueOnce([{ id: "adfs", label: "Contoso", type: "saml" }]);
    const ada: AdminUser = {
      ...alex,
      identities: [{ id: "i9", provider: "adfs", idp: "saml", subject: "g-94f0-persistent", email: "alex@example.com", createdAt: 1, lastLoginAt: Date.now() }],
      lastLogin: { at: Date.now(), authMethod: "sso", idpProvider: "adfs", idp: "saml" },
    };
    const { api, user } = await open([owner, ada]);
    const row = within(screen.getByLabelText("User Alex"));
    expect(await row.findByText("Contoso")).toBeOnTheScreen();
    expect(row.getByText("with SSO (Contoso)")).toBeOnTheScreen();
    await user.press(screen.getByLabelText("User Alex"));
    expect(await screen.findByText(/^Contoso · g-94f0-persistent \(alex@example\.com\)/)).toBeOnTheScreen();
    expect(screen.queryByLabelText("Tenant")).toBeNull();
    await user.type(screen.getByPlaceholderText("NameID at the SAML IdP"), "G-1234-persistent");
    await user.press(screen.getByText("Link"));
    expect(api.linkIdentity).toHaveBeenCalledWith("u1", { provider: "adfs", subject: "G-1234-persistent", tenant: undefined });
  });

  it("won't let you change your own or the owner's role or status", async () => {
    const { api, user } = await open([owner, alex]);
    await user.press(screen.getByLabelText("User Owner"));
    await act(async () => {});
    await user.press(screen.getByRole("radio", { name: "Member" }));
    await user.press(screen.getByText("Disable"));
    expect(api.patchUser).not.toHaveBeenCalled();
    expect(screen.getByText(/way back in/)).toBeOnTheScreen();
  });

  it("searches by name, email, role, and provider", () => {
    expect(matchesUser(alex, "GITHUB")).toBe(true);
    expect(matchesUser(alex, "alex@")).toBe(true);
    expect(matchesUser(alex, "admin")).toBe(false);
    expect(matchesUser(owner, "")).toBe(true);
  });
});
