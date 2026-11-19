import React from "react";
import { act, render, screen } from "@testing-library/react-native";
import { BotDetailsPanel } from "../BotDetailsPanel";
import type { BotView, Routine } from "../../src/types";

const mockCtx: Record<string, unknown> = { canWrite: true, can: () => true };
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));
jest.mock("../BotAvatar", () => ({ BotAvatar: () => null }));

const bot = (id: string, name: string): BotView => ({
  id,
  name,
  color: "#f5f5f5",
  shape: "waddle",
  harness: "claude",
  primary: false,
  hidden: false,
  unread: false,
  working: false,
});
const routine = (id: string, botId: string, name: string): Routine => ({
  id,
  bot_id: botId,
  name,
  cron: "0 9 * * *",
  instruction: "x",
  enabled: true,
});

describe("BotDetailsPanel", () => {
  it("never shows a routine list that arrives after switching Bots", async () => {
    const pending: Record<string, (list: Routine[]) => void> = {};
    Object.assign(mockCtx, {
      bots: [bot("a", "Ada"), bot("b", "Bob")],
      activeId: "a",
      fetchRoutines: jest.fn((id: string) => new Promise<Routine[]>((resolve) => (pending[id] = resolve))),
    });
    const ui = await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    mockCtx.activeId = "b";
    await ui.rerender(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);
    await act(async () => pending.b([routine("rb", "b", "Bob's digest")]));
    await act(async () => pending.a([routine("ra", "a", "Ada's digest")]));

    expect(screen.getByText("Bob's digest")).toBeOnTheScreen();
    expect(screen.queryByText("Ada's digest")).not.toBeOnTheScreen();
  });

  it("drops routines that belong to another Bot", async () => {
    Object.assign(mockCtx, {
      bots: [bot("b", "Bob")],
      activeId: "b",
      fetchRoutines: jest.fn(async () => [routine("rb", "b", "Mine"), routine("ra", "a", "Not mine")]),
    });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    expect(await screen.findByText("Mine")).toBeOnTheScreen();
    expect(screen.queryByText("Not mine")).not.toBeOnTheScreen();
  });

  it("offers read-only users nothing the server would refuse", async () => {
    Object.assign(mockCtx, {
      bots: [bot("b", "Bob")],
      activeId: "b",
      fetchRoutines: jest.fn(async () => [routine("rb", "b", "Mine")]),
      canWrite: false,
      can: (p: string) => ["account", "read", "review"].includes(p),
    });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    expect(await screen.findByText("Mine")).toBeOnTheScreen();
    expect(screen.queryByText("+ New routine")).not.toBeOnTheScreen();
    expect(screen.queryByText("Open screen")).not.toBeOnTheScreen();
    expect(screen.queryByText("Delete bot")).not.toBeOnTheScreen();
    expect(screen.getByLabelText("Pause Mine").props.disabled).toBe(true);
    Object.assign(mockCtx, { canWrite: true, can: () => true });
  });
});
