import React from "react";
import { act, render, screen, userEvent } from "@testing-library/react-native";
import { SecretsView } from "../SecretsView";
import SecretsScreen from "../../app/secrets";
import { ApiError } from "../../src/api";
import type { PersonalSecret } from "../../src/types";

const mockCtx: Record<string, unknown> = {};
const mockRedirect = jest.fn((_href: string) => null);
jest.mock("expo-router", () => ({
  Redirect: ({ href }: { href: string }) => mockRedirect(href),
  router: { canGoBack: () => false, back: jest.fn(), replace: jest.fn() },
}));
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

const NOV3 = Date.UTC(2026, 10, 3, 12) / 1000;
const NOV20 = Date.UTC(2026, 10, 20, 9) / 1000;

/** A fake server that keeps values the way botd does: in, never out. */
function fakeApi(initial: PersonalSecret[] = []) {
  let rows = [...initial];
  const values = new Map<string, string>();
  return {
    values,
    mySecrets: jest.fn(async () => rows.map((r) => ({ ...r }))),
    setMySecret: jest.fn(async (name: string, value: string) => {
      values.set(name, value);
      const old = rows.find((r) => r.name === name);
      const row = { name, createdAt: old?.createdAt ?? NOV20, updatedAt: NOV20, overrides: old?.overrides ?? false };
      rows = [...rows.filter((r) => r.name !== name), row].sort((a, b) => a.name.localeCompare(b.name));
      return row;
    }),
    deleteMySecret: jest.fn(async (name: string) => {
      rows = rows.filter((r) => r.name !== name);
    }),
  };
}

describe("SecretsView (ADR 0044)", () => {
  it("lists names and dates, never values", async () => {
    const api = fakeApi([
      { name: "GITHUB_TOKEN", createdAt: NOV3, updatedAt: NOV20, overrides: true },
      { name: "OPENAI_API_KEY", createdAt: NOV3, updatedAt: NOV3 },
    ]);
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    expect(await screen.findByText("OPENAI_API_KEY")).toBeOnTheScreen();
    expect(screen.getByText("Saved 3 Nov 2026")).toBeOnTheScreen();
    expect(screen.getByText("Saved 3 Nov 2026 · replaced 20 Nov 2026")).toBeOnTheScreen();
    expect(screen.getByText(/yours wins for your Bots/)).toBeOnTheScreen();
    expect(screen.getAllByText(/yours wins/)).toHaveLength(1);
  });

  it("adds a secret, then forgets the value it sent", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    expect(await screen.findByText("No secrets yet.")).toBeOnTheScreen();
    await user.type(screen.getByLabelText("Secret name"), "openai api key");
    await user.type(screen.getByLabelText("Secret value"), "sk-live-123");
    await user.press(screen.getByRole("button", { name: "Save secret" }));
    expect(api.setMySecret).toHaveBeenCalledWith("OPENAI_API_KEY", "sk-live-123");
    expect(await screen.findByText("Saved OPENAI_API_KEY. Your Bots get it on their next run.")).toBeOnTheScreen();
    expect(screen.getByText("OPENAI_API_KEY")).toBeOnTheScreen();
    expect(screen.getByLabelText("Secret value").props.value).toBe("");
    expect(screen.queryByText("sk-live-123")).toBeNull();
  });

  it("replaces a value under the same name", async () => {
    const api = fakeApi([{ name: "OPENAI_API_KEY", createdAt: NOV3, updatedAt: NOV3 }]);
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    await user.press(await screen.findByRole("button", { name: "Replace OPENAI_API_KEY" }));
    expect(screen.getByText("New value for OPENAI_API_KEY")).toBeOnTheScreen();
    expect(screen.queryByLabelText("Secret name")).toBeNull();
    await user.type(screen.getByLabelText("Secret value"), "sk-new");
    await user.press(screen.getByRole("button", { name: "Save new value for OPENAI_API_KEY" }));
    expect(api.setMySecret).toHaveBeenCalledWith("OPENAI_API_KEY", "sk-new");
    expect(await screen.findByText(/Replaced OPENAI_API_KEY/)).toBeOnTheScreen();
    expect(screen.getByText("Saved 3 Nov 2026 · replaced 20 Nov 2026")).toBeOnTheScreen();
    expect(screen.getByText("Add a secret")).toBeOnTheScreen();
  });

  it("warns that typing a name you have replaces it", async () => {
    const api = fakeApi([{ name: "OPENAI_API_KEY", createdAt: NOV3, updatedAt: NOV3 }]);
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    await user.type(await screen.findByLabelText("Secret name"), "OPENAI_API_KEY");
    expect(screen.getByText("You already have OPENAI_API_KEY; saving replaces its value.")).toBeOnTheScreen();
  });

  it("refuses reserved names before sending anything", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    await user.type(await screen.findByLabelText("Secret name"), "BOT_TOKEN");
    await user.type(screen.getByLabelText("Secret value"), "x");
    expect(screen.getByText("BOT_TOKEN is reserved by SuperBot.")).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Save secret" }));
    expect(api.setMySecret).not.toHaveBeenCalled();
  });

  it("deletes only after asking, and says what changes", async () => {
    const api = fakeApi([{ name: "GITHUB_TOKEN", createdAt: NOV3, updatedAt: NOV3, overrides: true }]);
    const confirm = jest.fn(async () => false);
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite confirm={confirm} />);
    await user.press(await screen.findByRole("button", { name: "Delete GITHUB_TOKEN" }));
    expect(confirm).toHaveBeenCalledWith("Delete GITHUB_TOKEN?", "Your Bots go back to the server's value. This can't be undone.");
    expect(api.deleteMySecret).not.toHaveBeenCalled();
    confirm.mockResolvedValueOnce(true);
    await user.press(screen.getByRole("button", { name: "Delete GITHUB_TOKEN" }));
    expect(api.deleteMySecret).toHaveBeenCalledWith("GITHUB_TOKEN");
    expect(await screen.findByText("Deleted GITHUB_TOKEN.")).toBeOnTheScreen();
    expect(screen.getByText("No secrets yet.")).toBeOnTheScreen();
  });

  it("shows read-only people their names without ways to change them", async () => {
    await render(<SecretsView api={fakeApi([{ name: "OPENAI_API_KEY", updatedAt: NOV3 }])} onBack={jest.fn()} canWrite={false} />);
    expect(await screen.findByText("OPENAI_API_KEY")).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Replace OPENAI_API_KEY" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete OPENAI_API_KEY" })).toBeNull();
    expect(screen.queryByLabelText("Secret value")).toBeNull();
    expect(screen.getByText(/Read-only accounts can't add or change secrets/)).toBeOnTheScreen();
  });

  it("shows a secret an admin keeps in your external folder as theirs to change (ADR 0174)", async () => {
    const api = fakeApi([
      { name: "ANTHROPIC_API_KEY", overrides: false, store: "vault", saved: false },
      { name: "OPENAI_API_KEY", createdAt: NOV3, updatedAt: NOV3, store: "aws", saved: true },
    ]);
    const confirm = jest.fn(async () => false);
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite confirm={confirm} />);
    expect(await screen.findByText("Set for you by an admin in HashiCorp Vault")).toBeOnTheScreen();
    expect(screen.getByText("Set for you by an admin in AWS Secrets Manager · it wins over the one you saved here")).toBeOnTheScreen();
    for (const name of ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]) {
      expect(screen.queryByRole("button", { name: `Replace ${name}` })).toBeNull();
    }
    expect(screen.queryByRole("button", { name: "Delete ANTHROPIC_API_KEY" })).toBeNull();
    await user.press(screen.getByRole("button", { name: "Delete OPENAI_API_KEY" }));
    expect(confirm).toHaveBeenCalledWith("Delete OPENAI_API_KEY?", "Your Bots keep the value an admin set for you in AWS Secrets Manager. This can't be undone.");
    await user.type(screen.getByLabelText("Secret name"), "ANTHROPIC_API_KEY");
    expect(screen.getByText("An admin set ANTHROPIC_API_KEY for you in HashiCorp Vault. That value wins, so one saved here isn't used.")).toBeOnTheScreen();
    await user.type(screen.getByLabelText("Secret value"), "sk-local");
    await user.press(screen.getByRole("button", { name: "Save new value for ANTHROPIC_API_KEY" }));
    expect(api.setMySecret).toHaveBeenCalledWith("ANTHROPIC_API_KEY", "sk-local");
    expect(await screen.findByText("Saved ANTHROPIC_API_KEY here, but your Bots keep the value an admin set for you in HashiCorp Vault.")).toBeOnTheScreen();
  });

  it("says what the server refused", async () => {
    const api = fakeApi();
    api.setMySecret.mockRejectedValueOnce(new ApiError("OPENAI_API_KEY is SuperBot's own; no Bot gets it.", 400));
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    await user.type(await screen.findByLabelText("Secret name"), "OPENAI_API_KEY");
    await user.type(screen.getByLabelText("Secret value"), "v");
    await user.press(screen.getByRole("button", { name: "Save secret" }));
    expect(await screen.findByText("OPENAI_API_KEY is SuperBot's own; no Bot gets it.")).toBeOnTheScreen();
    expect(screen.getByLabelText("Secret value").props.value).toBe("");
    expect(screen.getByLabelText("Secret name").props.value).toBe("OPENAI_API_KEY");
  });

  it("clears the value as it is sent and locks the form until the server answers", async () => {
    const api = fakeApi();
    let answer: () => void = () => {};
    api.setMySecret.mockImplementationOnce(
      (name: string) => new Promise((resolve) => (answer = () => resolve({ name, createdAt: NOV20, updatedAt: NOV20, overrides: false }))),
    );
    const user = userEvent.setup();
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    await user.type(await screen.findByLabelText("Secret name"), "GITHUB_TOKEN");
    await user.type(screen.getByLabelText("Secret value"), "ghp-123");
    await user.press(screen.getByRole("button", { name: "Save secret" }));
    expect(api.setMySecret).toHaveBeenCalledWith("GITHUB_TOKEN", "ghp-123");
    expect(screen.getByLabelText("Secret value").props.value).toBe("");
    expect(screen.getByLabelText("Secret value").props.editable).toBe(false);
    expect(screen.getByLabelText("Secret name").props.editable).toBe(false);
    await act(async () => answer());
    expect(await screen.findByText(/Saved GITHUB_TOKEN/)).toBeOnTheScreen();
    expect(screen.getByLabelText("Secret name").props.editable).toBe(true);
  });

  it("says so when the list can't load", async () => {
    const api = fakeApi();
    api.mySecrets.mockRejectedValueOnce(new ApiError("Sign in as a user to keep your own secrets.", 403));
    await render(<SecretsView api={api} onBack={jest.fn()} canWrite />);
    expect(await screen.findByText("Sign in as a user to keep your own secrets.")).toBeOnTheScreen();
  });

  it("titles the screen and goes back to the Bots", async () => {
    const onBack = jest.fn();
    await render(<SecretsView api={fakeApi()} onBack={onBack} canWrite />);
    expect(await screen.findByRole("header", { name: "Your secrets" })).toBeOnTheScreen();
    await userEvent.setup().press(screen.getByRole("button", { name: "Back to Bots" }));
    expect(onBack).toHaveBeenCalled();
  });
});

describe("secrets route", () => {
  beforeEach(() => mockRedirect.mockClear());

  it("waits for the saved session, then shows the list", async () => {
    Object.assign(mockCtx, { ready: false, api: null, canWrite: true });
    await render(<SecretsScreen />);
    expect(mockRedirect).not.toHaveBeenCalled();
    Object.assign(mockCtx, { ready: true, api: fakeApi([{ name: "OPENAI_API_KEY", updatedAt: NOV3 }]) });
    await render(<SecretsScreen />);
    expect(await screen.findByText("OPENAI_API_KEY")).toBeOnTheScreen();
  });

  it("sends people who aren't signed in to sign in", async () => {
    Object.assign(mockCtx, { ready: true, api: null });
    await render(<SecretsScreen />);
    expect(mockRedirect).toHaveBeenCalledWith("/");
  });
});
