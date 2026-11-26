import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react-native";
import { ChatView, peerLabel } from "../ChatView";
import { copyText } from "../../src/clipboard";
import { themes } from "../../src/theme";
import type { BotView, Message } from "../../src/types";

jest.mock("../BotAvatar", () => ({ BotAvatar: () => null }));
jest.mock("../ModelBar", () => {
  const { Text } = jest.requireActual("react-native");
  return {
    ModelBar: ({ tier }: { tier?: string }) => <Text>{`Model picker${tier ? ` for ${tier}` : ""}`}</Text>,
    PlanBar: ({ label }: { label: string }) => <Text>{`${label} plan`}</Text>,
  };
});
jest.mock("../../src/clipboard", () => ({ COPY_LABEL: "Copy", copyText: jest.fn(async () => true) }));

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
const list: Message[] = [
  { id: 1, botId: "b", role: "user", text: "Ask Ada", at: 1 },
  { id: 2, botId: "b", role: "peer", text: "Can you check the build?", fromBot: "a", at: 2 },
  { id: 3, botId: "b", role: "reply", text: "Done", fromBot: "gone", at: 3 },
  { id: 4, botId: "b", role: "bot", text: "All green", at: 4 },
];
const mockCtx: Record<string, unknown> = {
  bots: [bot("a", "Ada"), bot("b", "Bob")],
  activeId: "b",
  messages: { b: list },
  drafts: {},
  handoffs: {},
  approvals: [],
  canWrite: true,
  canOnBot: () => true,
  loadMessages: jest.fn(async () => {}),
};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

describe("ChatView", () => {
  afterEach(() => {
    mockCtx.bots = [bot("a", "Ada"), bot("b", "Bob")];
    mockCtx.me = undefined;
    mockCtx.activeId = "b";
    mockCtx.messages = { b: list };
    mockCtx.sendText = undefined;
  });

  it("shows a managed plan instead of a model picker, except to admins", async () => {
    const tier = { name: "pro", label: "Pro", managed: true };
    mockCtx.bots = [bot("a", "Ada"), { ...bot("b", "Bob"), tier }];
    mockCtx.me = { name: "Bea", role: "member" };
    const view = await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByText("Pro plan")).toBeOnTheScreen();
    expect(screen.queryByText(/Model picker/)).toBeNull();

    mockCtx.me = { name: "Owner", role: "admin" };
    await view.rerender(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByText("Model picker for pro")).toBeOnTheScreen();
  });

  it("keeps the model picker on self-host", async () => {
    mockCtx.bots = [bot("a", "Ada"), { ...bot("b", "Bob"), tier: { name: "self-host", label: "Self-host", managed: false } }];
    mockCtx.me = { name: "Bea", role: "member" };
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByText("Model picker")).toBeOnTheScreen();
  });

  it("puts a suggested starter in the message box once", async () => {
    const onPrefilled = jest.fn();
    const view = await render(
      <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} prefill="Set up a routine to " onPrefilled={onPrefilled} />,
    );
    const box = screen.getByLabelText("Message Bob");
    expect(box).toHaveDisplayValue("Set up a routine to ");
    expect(onPrefilled).toHaveBeenCalledTimes(1);

    await act(async () => fireEvent.changeText(box, "Set up a routine to water the plants"));
    await view.rerender(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} prefill={null} onPrefilled={onPrefilled} />);
    expect(box).toHaveDisplayValue("Set up a routine to water the plants");
    expect(onPrefilled).toHaveBeenCalledTimes(1);
  });

  it("says which Bot sent a Bot-to-Bot message", () => {
    expect(peerLabel(list[1], [bot("a", "Ada")])).toBe("From Ada");
    expect(peerLabel(list[2], [bot("a", "Ada")])).toBe("Reply from another Bot");
  });

  it("labels Bot-to-Bot messages and copies a Bot's words, not the user's", async () => {
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByText("From Ada")).toBeOnTheScreen();
    expect(screen.getByText("Reply from another Bot")).toBeOnTheScreen();
    expect(screen.getAllByLabelText("Copy message")).toHaveLength(3);

    await act(async () => fireEvent.press(screen.getAllByLabelText("Copy message")[2]));
    expect(copyText).toHaveBeenCalledWith("All green");
  });

  it("sends the trimmed message from the send button, and nothing when it's empty", async () => {
    const sendText = jest.fn(async () => {});
    mockCtx.sendText = sendText;
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
    expect(sendText).not.toHaveBeenCalled();

    await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "  Ship it  "));
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
    expect(sendText).toHaveBeenCalledWith("Ship it");
    expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("");
  });

  it("greets you in a Bot's empty chat", async () => {
    mockCtx.messages = { b: [] };
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByText("Say hello to Bob")).toBeOnTheScreen();
  });

  it("asks you to pick a Bot when none is open", async () => {
    mockCtx.activeId = null;
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByText("Pick a bot to start chatting")).toBeOnTheScreen();
    expect(screen.queryByLabelText(/^Message /)).toBeNull();
  });

  it("shows keyboard focus on the message box", async () => {
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    const box = screen.getByLabelText("Message Bob");
    const accent = { borderColor: themes.light.c.accent };
    expect(box.parent).not.toHaveStyle(accent);

    await act(async () => fireEvent(box, "focus"));
    expect(box.parent).toHaveStyle(accent);

    await act(async () => fireEvent(box, "blur"));
    expect(box.parent).not.toHaveStyle(accent);
  });
});
