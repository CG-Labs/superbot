import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react-native";
import { ChatView, peerLabel } from "../ChatView";
import { copyText } from "../../src/clipboard";
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
});
