import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react-native";
import { BotDetailsPanel } from "../BotDetailsPanel";
import { hasAccess } from "../../src/access";
import * as dialogs from "../../src/dialogs";
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

  it("moves a Bot to another harness, for those who manage it", async () => {
    const patchBot = jest.fn(async () => {});
    Object.assign(mockCtx, { bots: [bot("b", "Bob")], activeId: "b", fetchRoutines: jest.fn(async () => []), patchBot, harnesses: ["claude", "hermes"] });
    const ui = await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);

    await act(async () => fireEvent.press(screen.getByText("Hermes Agent")));
    expect(patchBot).toHaveBeenCalledWith("b", { harness: "hermes" });
    patchBot.mockClear();
    await act(async () => fireEvent.press(screen.getByRole("radio", { name: "Claude Code" })));
    expect(patchBot).not.toHaveBeenCalled();

    Object.assign(mockCtx, { bots: [shared("operate")] });
    await ui.rerender(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);
    expect(screen.queryByText("Hermes Agent")).not.toBeOnTheScreen();
    Object.assign(mockCtx, { harnesses: undefined });
  });

  it("offers an admin the harnesses of the owner's plan, not their own", async () => {
    Object.assign(mockCtx, {
      bots: [{ ...bot("b", "Bob"), harnesses: ["claude", "codex"] }],
      activeId: "b",
      fetchRoutines: jest.fn(async () => []),
      patchBot: jest.fn(async () => {}),
      harnesses: ["claude", "hermes"],
    });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} />);
    expect(screen.getByRole("radio", { name: "Codex" })).toBeOnTheScreen();
    expect(screen.queryByText("Hermes Agent")).not.toBeOnTheScreen();
    Object.assign(mockCtx, { harnesses: undefined });
  });

  it("asks before deleting a Bot", async () => {
    const confirm = jest.spyOn(dialogs, "confirmAsync").mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const deleteBot = jest.fn(async () => {});
    const onClose = jest.fn();
    Object.assign(mockCtx, { bots: [bot("b", "Bob")], activeId: "b", fetchRoutines: jest.fn(async () => []), deleteBot });
    await render(<BotDetailsPanel visible onClose={onClose} onOpenScreen={jest.fn()} />);

    await act(async () => fireEvent.press(screen.getByText("Delete bot")));
    expect(confirm).toHaveBeenCalledWith("Delete Bob?", expect.stringContaining("erases its chat"));
    expect(deleteBot).not.toHaveBeenCalled();
    await act(async () => fireEvent.press(screen.getByText("Delete bot")));
    expect(deleteBot).toHaveBeenCalledWith("b");
    expect(onClose).toHaveBeenCalled();
    confirm.mockRestore();
  });

  it("starts a chat from a suggested prompt and closes", async () => {
    const onUsePrompt = jest.fn();
    const onClose = jest.fn();
    Object.assign(mockCtx, { bots: [{ ...bot("b", "Bob"), prompts: ["Check the build"] }], activeId: "b", fetchRoutines: jest.fn(async () => []) });
    await render(<BotDetailsPanel visible onClose={onClose} onOpenScreen={jest.fn()} onUsePrompt={onUsePrompt} />);

    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Ask Bob: Check the build" })));
    expect(onUsePrompt).toHaveBeenCalledWith("Check the build");
    expect(onClose).toHaveBeenCalled();
  });

  it("shows the default prompts when the Bot has none saved", async () => {
    Object.assign(mockCtx, { bots: [bot("b", "Bob")], activeId: "b", fetchRoutines: jest.fn(async () => []) });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} onUsePrompt={jest.fn()} />);
    expect(screen.getByRole("button", { name: "Start a message: Set up a routine to…" })).toBeOnTheScreen();
  });

  it("lets those who manage the Bot edit its prompts", async () => {
    const patchBot = jest.fn(async () => {});
    Object.assign(mockCtx, { bots: [{ ...bot("b", "Bob"), prompts: ["Old"] }], activeId: "b", fetchRoutines: jest.fn(async () => []), patchBot });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} onUsePrompt={jest.fn()} />);

    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Edit suggested prompts" })));
    await act(async () => fireEvent.changeText(screen.getByLabelText("Prompt 1"), "New"));
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Save prompts" })));
    expect(patchBot).toHaveBeenCalledWith("b", { prompts: ["New"] });
    expect(screen.queryByText("Suggested prompts")).not.toBeOnTheScreen();
  });

  it("lets operators use prompts but not edit them", async () => {
    Object.assign(mockCtx, { bots: [{ ...shared("operate"), prompts: ["Check the build"] }], activeId: "b", fetchRoutines: jest.fn(async () => []) });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} onUsePrompt={jest.fn()} />);

    expect(screen.getByRole("button", { name: "Ask Bob: Check the build" })).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Edit suggested prompts" })).not.toBeOnTheScreen();
  });

  it("lets a viewer look but not run the Bot", async () => {
    Object.assign(mockCtx, { bots: [shared("view")], activeId: "b", fetchRoutines: jest.fn(async () => [routine("rb", "b", "Mine")]) });
    await render(<BotDetailsPanel visible onClose={jest.fn()} onOpenScreen={jest.fn()} onUsePrompt={jest.fn()} />);

    expect(await screen.findByText("Mine")).toBeOnTheScreen();
    expect(screen.queryByText("Suggested")).not.toBeOnTheScreen();
    expect(screen.queryByText("+ New routine")).not.toBeOnTheScreen();
    expect(screen.queryByText("Open screen")).not.toBeOnTheScreen();
    expect(screen.getByLabelText("Pause Mine").props.disabled).toBe(true);
    expect(screen.getByLabelText("Make private").props.disabled).toBe(true);
  });
});
