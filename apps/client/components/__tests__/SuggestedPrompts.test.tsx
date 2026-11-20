import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { SuggestedPrompts } from "../SuggestedPrompts";

describe("SuggestedPrompts", () => {
  it("offers each prompt as a button that says what tapping does", async () => {
    const user = userEvent.setup();
    const onUse = jest.fn();
    await render(<SuggestedPrompts botName="Scout" prompts={["Check the build", "Set up a routine to…"]} onUse={onUse} />);

    expect(screen.getByRole("heading", { name: "Suggested" })).toBeOnTheScreen();
    const send = screen.getByRole("button", { name: "Ask Scout: Check the build" });
    expect(send.props.accessibilityHint).toBe("Sends it now");
    const starter = screen.getByRole("button", { name: "Start a message: Set up a routine to…" });
    expect(starter.props.accessibilityHint).toMatch(/message box/);

    await user.press(starter);
    expect(onUse).toHaveBeenCalledWith("Set up a routine to…");
    expect(screen.queryByRole("button", { name: "Edit suggested prompts" })).not.toBeOnTheScreen();
  });

  it("lets managers edit, and tells them when there are none", async () => {
    const user = userEvent.setup();
    const onEdit = jest.fn();
    await render(<SuggestedPrompts botName="Scout" prompts={[]} onUse={jest.fn()} onEdit={onEdit} />);

    expect(screen.getByText("No suggested prompts")).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Edit suggested prompts" }));
    expect(onEdit).toHaveBeenCalled();
  });

  it("shows nothing when there are none and nothing to edit", async () => {
    await render(<SuggestedPrompts botName="Scout" prompts={[]} onUse={jest.fn()} />);
    expect(screen.queryByText("Suggested")).not.toBeOnTheScreen();
  });
});
