import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react-native";
import { BotDetailsPanel } from "../BotDetailsPanel";
import { hasAccess } from "../../src/access";
import type { BotAccess, BotView, Routine } from "../../src/types";

const mockCtx: Record<string, unknown> = {
  canWrite: true,
  can: () => true,
  canOnBot: (b: BotView | undefined, need: BotAccess) => hasAccess(b, need, mockCtx.canWrite as boolean),
  me: { name: "Ada", id: "u1" },
};
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

  const shared = (access: BotAccess): BotView => ({
    ...bot("b", "Bob"),
    owner: { id: "u1", name: "Ada" },
    visibility: "shared",
    access,
  });

  it("lets the owner make a shared Bot private", async () => {
    const setBotVisibility = jest.fn(async () => {});
    Object.assign(mockCtx, { bots: [shared("manage")], activeId: "b", fetchRoutines: jest.fn(async () => []), setBotVisibility });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    expect(screen.getByText("Shared with everyone · owned by you")).toBeOnTheScreen();
    const toggle = screen.getByLabelText("Make private");
    expect(toggle.props.disabled).toBeFalsy();
    await act(async () => fireEvent(toggle, "valueChange", false));
    expect(setBotVisibility).toHaveBeenCalledWith("b", "private");
    expect(screen.getByText("Delete bot")).toBeOnTheScreen();
  });

  it("lets an operator run a Bot but not change who sees it", async () => {
    Object.assign(mockCtx, {
      bots: [{ ...shared("operate"), owner: { id: "u2", name: "Grace" }, visibility: "private" }],
      activeId: "b",
      fetchRoutines: jest.fn(async () => [routine("rb", "b", "Mine")]),
    });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    expect(await screen.findByText("+ New routine")).toBeOnTheScreen();
    expect(screen.getByText("Open screen")).toBeOnTheScreen();
    expect(screen.getByText("Private · owned by Grace")).toBeOnTheScreen();
    expect(screen.getByLabelText("Share with everyone").props.disabled).toBe(true);
    expect(screen.queryByText("Delete bot")).not.toBeOnTheScreen();
  });

  it("lets a viewer look but not run the Bot", async () => {
    Object.assign(mockCtx, { bots: [shared("view")], activeId: "b", fetchRoutines: jest.fn(async () => [routine("rb", "b", "Mine")]) });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    expect(await screen.findByText("Mine")).toBeOnTheScreen();
    expect(screen.queryByText("+ New routine")).not.toBeOnTheScreen();
    expect(screen.queryByText("Open screen")).not.toBeOnTheScreen();
    expect(screen.getByLabelText("Pause Mine").props.disabled).toBe(true);
    expect(screen.getByLabelText("Make private").props.disabled).toBe(true);
  });
});
