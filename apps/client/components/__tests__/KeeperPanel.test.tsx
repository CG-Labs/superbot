import React from "react";
import * as RN from "react-native";
import { act, render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { KeeperPanel } from "../KeeperPanel";
import { confirmAsync } from "../../src/dialogs";
import { themes } from "../../src/theme";
import type { BotAccessView, BotKeeper } from "../../src/types";

jest.mock("../../src/dialogs", () => ({ confirmAsync: jest.fn(async () => true) }));

const keeper = (id: string, name: string, extra: Partial<BotKeeper> = {}): BotKeeper => ({ id, name, role: "member", status: "active", keptBots: 0, full: false, ...extra });

const view = (extra: Partial<BotAccessView> = {}): BotAccessView => ({
  botId: "b1",
  owner: { id: "u1", name: "Ada", email: "ada@example.com" },
  visibility: "private",
  access: "manage",
  keepers: [keeper("sa1", "CI"), keeper("sa2", "Nightly", { full: true })],
  maxKeptBots: 20,
  ...extra,
});

function mockApi(first: BotAccessView) {
  return {
    getBotAccess: jest.fn(async () => first),
    keepBot: jest.fn(async (_id: string, sa: string) => view({ serviceAccount: { id: sa, name: "CI", email: null } })),
    releaseKeptBot: jest.fn(async () => view()),
  };
}

describe("KeeperPanel (ADR 0229)", () => {
  beforeEach(() => jest.clearAllMocks());

  it("hands the Bot to one of its owner's accounts that isn't full, after asking", async () => {
    const api = mockApi(view());
    const u = userEvent.setup();
    await render(<KeeperPanel api={api} botId="b1" botName="Ledger" />);
    expect(await screen.findByText("Kept by a service account")).toBeTruthy();
    expect(screen.queryByText("Nightly")).toBeNull();
    await u.press(screen.getByText("CI"));
    await waitFor(() => expect(api.keepBot).toHaveBeenCalledWith("b1", "sa1"));
    expect(confirmAsync).toHaveBeenLastCalledWith("Let CI keep Ledger?", expect.stringMatching(/owner's keys and memory/), "Hand it over");
    expect(screen.getByRole("radio", { name: "CI" })).toBeChecked();
  });

  it("takes it back, and keeps the one keeping it offered even when full", async () => {
    const api = mockApi(view({ serviceAccount: { id: "sa2", name: "Nightly", email: null } }));
    const u = userEvent.setup();
    await render(<KeeperPanel api={api} botId="b1" botName="Ledger" />);
    expect(await screen.findByRole("radio", { name: "Nightly" })).toBeChecked();
    await u.press(screen.getByText("Nobody"));
    await waitFor(() => expect(api.releaseKeptBot).toHaveBeenCalledWith("b1"));
    expect(confirmAsync).toHaveBeenLastCalledWith("Take Ledger back from Nightly?", expect.any(String), "Take it back");
  });

  it("does nothing when they say no, and shows the server's refusal", async () => {
    const api = mockApi(view());
    (confirmAsync as jest.Mock).mockResolvedValueOnce(false);
    const u = userEvent.setup();
    await render(<KeeperPanel api={api} botId="b1" botName="Ledger" />);
    await u.press(await screen.findByText("CI"));
    await waitFor(() => expect(confirmAsync).toHaveBeenCalled());
    expect(api.keepBot).not.toHaveBeenCalled();

    api.keepBot.mockRejectedValueOnce(new Error("CI keeps 20 Bots already"));
    await u.press(screen.getByText("CI"));
    expect(await screen.findByRole("alert")).toHaveTextContent("CI keeps 20 Bots already");
    expect(api.getBotAccess).toHaveBeenCalledTimes(2);
  });

  it("reloads when another session changes its keeper, and a slower older read doesn't win", async () => {
    let answerFirst: (v: BotAccessView) => void = () => {};
    const api = mockApi(view());
    api.getBotAccess
      .mockImplementationOnce(() => new Promise<BotAccessView>((resolve) => (answerFirst = resolve)))
      .mockResolvedValueOnce(view({ serviceAccount: { id: "sa2", name: "Nightly", email: null } }));
    const { rerender } = await render(<KeeperPanel api={api} botId="b1" botName="Ledger" keptBy={null} />);
    await rerender(<KeeperPanel api={api} botId="b1" botName="Ledger" keptBy="sa2" />);
    expect(await screen.findByRole("radio", { name: "Nightly" })).toBeChecked();
    answerFirst(view());
    await waitFor(() => expect(api.getBotAccess).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("radio", { name: "Nightly" })).toBeChecked();
  });

  it("shows nothing when the server offers no accounts", async () => {
    const api = mockApi(view({ keepers: undefined }));
    await render(<KeeperPanel api={api} botId="b1" botName="Ledger" />);
    await waitFor(() => expect(api.getBotAccess).toHaveBeenCalled());
    expect(screen.queryByText("Kept by a service account")).toBeNull();
  });

  it("shows nothing while the accounts load, then why they couldn't, with a retry", async () => {
    const api = mockApi(view());
    let fail: (e: Error) => void = () => {};
    api.getBotAccess.mockImplementationOnce(() => new Promise<BotAccessView>((_, reject) => (fail = reject)));
    await render(<KeeperPanel api={api} botId="b1" botName="Ledger" />);
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.queryByText("Kept by a service account")).toBeNull();

    await act(async () => fail(new TypeError("Failed to fetch")));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load the service accounts. Can't reach the server. Check your connection and try again.");
    await userEvent.setup().press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Kept by a service account")).toBeOnTheScreen();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it.each(["light", "dark"] as const)("follows the device's %s setting", async (scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(scheme);
    await render(<KeeperPanel api={mockApi(view())} botId="b1" botName="Ledger" />);
    expect(await screen.findByText("Kept by a service account")).toHaveStyle({ color: themes[scheme].c.textMuted });
    jest.restoreAllMocks();
  });
});
