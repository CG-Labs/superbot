import React from "react";
import * as RN from "react-native";
import { act, fireEvent, render, screen, userEvent } from "@testing-library/react-native";
import { CreateBotModal } from "../CreateBotModal";
import { botColors, themes } from "../../src/theme";

jest.mock("../BotAvatar", () => ({ BotAvatar: () => null }));

const mockCtx: Record<string, unknown> = {};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

const createBot = jest.fn();

beforeEach(() => {
  createBot.mockReset().mockResolvedValue({ id: "b9" });
  Object.assign(mockCtx, { createBot, harnesses: ["claude", "codex"], defaultHarness: "claude", me: { tier: null } });
});
afterEach(() => jest.restoreAllMocks());

function open(props: Partial<React.ComponentProps<typeof CreateBotModal>> = {}) {
  return render(<CreateBotModal visible onClose={jest.fn()} onCreated={jest.fn()} {...props} />);
}

describe("CreateBotModal", () => {
  it.each(["light", "dark"] as const)("draws the sheet in the %s palette", async (scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(scheme);
    const c = themes[scheme].c;
    await open();
    const title = screen.getByRole("heading", { name: "New bot" });
    expect(title).toHaveStyle({ color: c.text });
    expect(title.parent).toHaveStyle({ backgroundColor: c.elevated });
    expect(screen.getByLabelText("Bot name")).toHaveStyle({ backgroundColor: c.bg, color: c.text });
    expect(screen.getByLabelText("Bot name").props.placeholderTextColor).toBe(c.textFaint);
    expect(screen.getByRole("radio", { checked: true })).toHaveStyle({ backgroundColor: c.selected, borderColor: c.accentBorder });
    expect(screen.getByRole("button", { name: "Create" })).toHaveStyle({ backgroundColor: c.accent });
    expect(screen.getByText("Create")).toHaveStyle({ color: c.onAccent });
  });

  it("names its choices and says which are picked", async () => {
    await open();
    expect(screen.getByRole("button", { name: "Shape waddle" })).toBeSelected();
    expect(screen.getByRole("button", { name: "Shape drop" })).not.toBeSelected();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Shape drop" })));
    expect(screen.getByRole("button", { name: "Shape drop" })).toBeSelected();
    expect(screen.getByRole("button", { name: "Shape waddle" })).not.toBeSelected();

    expect(screen.getByRole("button", { name: "Colour White" })).toBeSelected();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Colour Red" })));
    expect(screen.getByRole("button", { name: "Colour Red" })).toBeSelected();
    expect(screen.getByRole("button", { name: "Colour White" })).not.toBeSelected();

    expect(screen.getByRole("radio", { name: /default/ })).toBeChecked();
    await act(async () => fireEvent.press(screen.getByRole("radio", { name: "Codex" })));
    expect(screen.getByRole("radio", { name: "Codex" })).toBeChecked();
    expect(screen.getByRole("radio", { name: /default/ })).not.toBeChecked();
  });

  it("creates the Bot with what was picked, busy while it's made", async () => {
    let finish!: (b: { id: string }) => void;
    createBot.mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)));
    const onCreated = jest.fn();
    const onClose = jest.fn();
    const user = userEvent.setup();
    await open({ onCreated, onClose });
    expect(screen.getByRole("button", { name: "Create" })).toBeDisabled();
    await user.type(screen.getByLabelText("Bot name"), " Scout ");
    await user.press(screen.getByRole("button", { name: "Shape drop" }));
    await user.press(screen.getByRole("button", { name: "Colour Brown" }));
    await user.press(screen.getByRole("radio", { name: "Codex" }));
    await user.press(screen.getByRole("button", { name: "Create" }));
    expect(createBot).toHaveBeenCalledWith({ name: "Scout", color: botColors[1], shape: "drop", harness: "codex" });
    const busy = screen.getByRole("button", { name: "Creating…" });
    expect(busy).toBeDisabled();
    expect(busy).toBeBusy();
    await act(async () => finish({ id: "b9" }));
    expect(onCreated).toHaveBeenCalledWith("b9");
    expect(onClose).toHaveBeenCalled();
  });

  it("leaves the harness to the server unless one is picked", async () => {
    const user = userEvent.setup();
    await open();
    await user.type(screen.getByLabelText("Bot name"), "Ada");
    await user.press(screen.getByRole("button", { name: "Create" }));
    expect(createBot).toHaveBeenCalledWith(expect.objectContaining({ name: "Ada", harness: undefined }));
  });

  it("says why it couldn't create the Bot, in plain words", async () => {
    createBot.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const onClose = jest.fn();
    const user = userEvent.setup();
    await open({ onClose });
    await user.type(screen.getByLabelText("Bot name"), "Ada");
    await user.press(screen.getByRole("button", { name: "Create" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Can't reach the server. Check your connection and try again.");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Create" })).toBeEnabled();
  });

  it("cancels", async () => {
    const onClose = jest.fn();
    await open({ onClose });
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Cancel" })));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(createBot).not.toHaveBeenCalled();
  });
});
