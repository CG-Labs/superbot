import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react-native";
import { ChatView, peerLabel } from "../ChatView";
import { ToastProvider } from "../Toast";
import { copyText } from "../../src/clipboard";
import { themes } from "../../src/theme";
import type { BotView, Message } from "../../src/types";
import { endUnsent } from "../../src/unsent";

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
  api: {},
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
    mockCtx.api = {};
    mockCtx.bots = [bot("a", "Ada"), bot("b", "Bob")];
    mockCtx.me = undefined;
    mockCtx.activeId = "b";
    mockCtx.messages = { b: list };
    mockCtx.sendText = undefined;
    mockCtx.stopBot = undefined;
    mockCtx.loadMessages = jest.fn(async () => {});
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
    expect(sendText).toHaveBeenCalledWith("Ship it", undefined, "b");
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

  it("shows the chat's outline while its history loads", async () => {
    let done!: () => void;
    mockCtx.messages = {};
    mockCtx.loadMessages = jest.fn(() => new Promise<void>((r) => (done = r)));
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByRole("progressbar", { name: "Loading messages" })).toBeOnTheScreen();

    mockCtx.messages = { b: list };
    await act(async () => done());
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.getByText("All green")).toBeOnTheScreen();
  });

  it("says why a chat couldn't load and tries again", async () => {
    mockCtx.messages = {};
    mockCtx.loadMessages = jest
      .fn()
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockImplementationOnce(async () => {
        mockCtx.messages = { b: list };
      });
    await render(<ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/Couldn't load this chat.*Can't reach the server/);

    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Try again" })));
    expect(mockCtx.loadMessages).toHaveBeenCalledTimes(2);
    expect(screen.getByText("All green")).toBeOnTheScreen();
  });

  it("offers a first Bot when there are none", async () => {
    const onNewBot = jest.fn();
    mockCtx.bots = [];
    mockCtx.activeId = null;
    await render(<ChatView onOpenDetails={jest.fn()} onNewBot={onNewBot} onToggleScreen={jest.fn()} />);
    expect(screen.getByRole("heading", { name: "No Bots yet" })).toBeOnTheScreen();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "New Bot" })));
    expect(onNewBot).toHaveBeenCalledTimes(1);
  });

  it("gives back a message that didn't send, with a toast to retry it", async () => {
    const sendText = jest.fn().mockRejectedValueOnce(new TypeError("Network request failed")).mockResolvedValueOnce(undefined);
    mockCtx.sendText = sendText;
    await render(
      <ToastProvider>
        <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />
      </ToastProvider>,
    );
    await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "Ship it"));
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
    expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it");
    expect(screen.getByRole("alert")).toHaveTextContent(/Couldn't send your message\. Can't reach the server/);

    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Retry" })));
    expect(sendText).toHaveBeenNthCalledWith(2, "Ship it", undefined, "b");
    expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("drops the old Retry once you resend the message yourself", async () => {
    const sendText = jest.fn().mockRejectedValueOnce(new TypeError("Network request failed")).mockResolvedValue(undefined);
    mockCtx.sendText = sendText;
    await render(
      <ToastProvider>
        <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />
      </ToastProvider>,
    );
    await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "Ship it"));
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
    expect(screen.getByRole("button", { name: "Retry" })).toBeOnTheScreen();

    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    expect(sendText).toHaveBeenCalledTimes(2);
  });

  describe("a send that fails after its chat closed", () => {
    const ui = (open: boolean) => (
      <ToastProvider>{open ? <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} /> : null}</ToastProvider>
    );
    const sendThenClose = async () => {
      let fail!: (err: Error) => void;
      const sendText = jest.fn(() => new Promise<void>((_, reject) => (fail = reject)));
      mockCtx.sendText = sendText;
      const view = await render(ui(true));
      await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "Ship it"));
      await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
      await view.rerender(ui(false));
      return { view, sendText, fail: (err: Error) => act(async () => fail(err)) };
    };

    it("comes back when the chat opens again, and its Retry goes away", async () => {
      const { view, fail } = await sendThenClose();
      await fail(new TypeError("Network request failed"));
      expect(screen.getByRole("button", { name: "Retry" })).toBeOnTheScreen();

      await view.rerender(ui(true));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it");
      expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    });

    it("is forgotten on sign-out, so the next account never sees it", async () => {
      const { view, fail } = await sendThenClose();
      endUnsent(mockCtx.api as object);
      await fail(new TypeError("Network request failed"));
      expect(screen.queryByTestId("toast")).toBeNull();

      mockCtx.api = {};
      await view.rerender(ui(true));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("");
    });

    it("can't be retried after sign-out", async () => {
      const { sendText, fail } = await sendThenClose();
      await fail(new TypeError("Network request failed"));
      endUnsent(mockCtx.api as object);
      await act(async () => fireEvent.press(screen.getByRole("button", { name: "Retry" })));
      expect(sendText).toHaveBeenCalledTimes(1);
    });
  });

  describe("a failed message back in the box", () => {
    const ui = (open = true) => (
      <ToastProvider>{open ? <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} /> : null}</ToastProvider>
    );
    const failInBox = async (words = "Ship it") => {
      const sendText = jest.fn().mockRejectedValueOnce(new TypeError("Network request failed")).mockResolvedValue(undefined);
      mockCtx.sendText = sendText;
      const view = await render(ui());
      await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), words));
      await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue(words);
      return { view, sendText };
    };

    it("survives closing the chat, and its Retry goes once it's back", async () => {
      const { view } = await failInBox();
      await view.rerender(ui(false));
      expect(screen.getByRole("button", { name: "Retry" })).toBeOnTheScreen();
      await view.rerender(ui(true));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it");
      expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    });

    it("survives closing the chat as you edited it", async () => {
      const { view } = await failInBox();
      await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "Ship it now"));
      await view.rerender(ui(false));
      await view.rerender(ui(true));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it now");

      await view.rerender(ui(false));
      await view.rerender(ui(true));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it now");
    });

    it("isn't sent twice when Retry is pressed after the chat closed", async () => {
      const { view, sendText } = await failInBox();
      await view.rerender(ui(false));
      await act(async () => fireEvent.press(screen.getByRole("button", { name: "Retry" })));
      expect(sendText).toHaveBeenNthCalledWith(2, "Ship it", undefined, "b");

      await view.rerender(ui(true));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("");
    });

    it("stays with its Bot when you open another, so it isn't sent there", async () => {
      const { view, sendText } = await failInBox();
      mockCtx.activeId = "a";
      await view.rerender(ui());
      expect(screen.getByLabelText("Message Ada")).toHaveDisplayValue("");
      await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
      expect(sendText).toHaveBeenCalledTimes(1);

      mockCtx.activeId = "b";
      await view.rerender(ui());
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it");
      expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    });

    it("isn't kept once you clear the box", async () => {
      const { view } = await failInBox();
      await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), ""));
      await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "Something else"));
      mockCtx.activeId = "a";
      await view.rerender(ui());
      expect(screen.getByLabelText("Message Ada")).toHaveDisplayValue("Something else");
    });

    it("comes back later when a suggested starter takes the box", async () => {
      const { view } = await failInBox();
      const withPrefill = (prefill: string | null) => (
        <ToastProvider>
          <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} prefill={prefill} onPrefilled={jest.fn()} />
        </ToastProvider>
      );
      await view.rerender(withPrefill("Set up a routine to "));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Set up a routine to ");
      await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), ""));
      await view.rerender(withPrefill(null));
      mockCtx.activeId = "a";
      await view.rerender(withPrefill(null));
      mockCtx.activeId = "b";
      await view.rerender(withPrefill(null));
      expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it");
    });
  });

  it("keeps a failed message with its own Bot when you've moved to another", async () => {
    let fail!: (err: Error) => void;
    const sendText = jest
      .fn()
      .mockImplementationOnce(() => new Promise<void>((_, reject) => (fail = reject)))
      .mockResolvedValueOnce(undefined);
    mockCtx.sendText = sendText;
    const ui = () => (
      <ToastProvider>
        <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />
      </ToastProvider>
    );
    const view = await render(ui());
    await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), "Ship it"));
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));

    mockCtx.activeId = "a";
    await view.rerender(ui());
    await act(async () => fail(new TypeError("Network request failed")));
    expect(screen.getByLabelText("Message Ada")).toHaveDisplayValue("");

    await act(async () => fireEvent.changeText(screen.getByLabelText("Message Ada"), "Hi Ada"));
    mockCtx.activeId = "b";
    await view.rerender(ui());
    expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Hi Ada");

    await act(async () => fireEvent.changeText(screen.getByLabelText("Message Bob"), ""));
    mockCtx.activeId = "a";
    await view.rerender(ui());
    mockCtx.activeId = "b";
    await view.rerender(ui());
    expect(screen.getByLabelText("Message Bob")).toHaveDisplayValue("Ship it");
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();

    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Send" })));
    expect(sendText).toHaveBeenNthCalledWith(2, "Ship it", undefined, "b");
  });

  it("names the header, the stop button and the chosen option for screen readers", async () => {
    const stopBot = jest.fn(async () => {});
    mockCtx.stopBot = stopBot;
    mockCtx.bots = [bot("a", "Ada"), { ...bot("b", "Bob"), working: true }];
    mockCtx.messages = {
      b: [{ id: 9, botId: "b", role: "bot", text: "Which?", at: 9, question: { title: "Pick one", options: ["Red", "Blue"], picked: 1 } }],
    };
    const onOpenDetails = jest.fn();
    await render(<ChatView onOpenDetails={onOpenDetails} onToggleScreen={jest.fn()} />);
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Bob, Claude Code" })));
    expect(onOpenDetails).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Blue" })).toBeSelected();
    expect(screen.getByRole("button", { name: "Red" })).not.toBeSelected();
    expect(screen.getByRole("button", { name: "Red" })).toBeDisabled();
    expect(screen.getByText("Working…")).toHaveProp("aria-live", "polite");
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Stop Bob" })));
    expect(stopBot).toHaveBeenCalledWith("b");
  });

  it("says when stopping fails instead of failing silently", async () => {
    mockCtx.stopBot = jest.fn().mockRejectedValue(new Error("Not allowed"));
    mockCtx.bots = [bot("a", "Ada"), { ...bot("b", "Bob"), working: true }];
    await render(
      <ToastProvider>
        <ChatView onOpenDetails={jest.fn()} onToggleScreen={jest.fn()} />
      </ToastProvider>,
    );
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Stop Bob" })));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't stop it. Not allowed");
  });
});
