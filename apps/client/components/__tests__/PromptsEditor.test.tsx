import React from "react";
import { act, fireEvent, render, screen, userEvent } from "@testing-library/react-native";
import { PromptsEditor } from "../PromptsEditor";
import { DEFAULT_PROMPTS } from "../../src/prompts";

describe("PromptsEditor", () => {
  it("starts from the defaults and saves an edited, cleaned list", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockResolvedValue(undefined);
    await render(<PromptsEditor prompts={DEFAULT_PROMPTS} custom={false} onSave={onSave} onCancel={jest.fn()} />);

    expect(screen.getByLabelText("Prompt 1")).toHaveDisplayValue(DEFAULT_PROMPTS[0]);
    expect(screen.queryByRole("button", { name: "Use the default prompts" })).not.toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Remove prompt 2" }));
    await user.press(screen.getByRole("button", { name: "Add prompt" }));
    await user.type(screen.getByLabelText("Prompt 3"), "  Check the build ");
    await user.press(screen.getByRole("button", { name: "Add prompt" }));
    await user.press(screen.getByRole("button", { name: "Save prompts" }));

    expect(onSave).toHaveBeenCalledWith([DEFAULT_PROMPTS[0], DEFAULT_PROMPTS[2], "Check the build"]);
  });

  it("goes back to the defaults, and stops adding at six", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockResolvedValue(undefined);
    const six = ["1", "2", "3", "4", "5", "6"];
    await render(<PromptsEditor prompts={six} custom onSave={onSave} onCancel={jest.fn()} />);

    expect(screen.queryByRole("button", { name: "Add prompt" })).not.toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Use the default prompts" }));
    expect(onSave).toHaveBeenCalledWith(null);
  });

  it("can save none, which hides them", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockResolvedValue(undefined);
    await render(<PromptsEditor prompts={["Only one"]} custom onSave={onSave} onCancel={jest.fn()} />);

    await user.press(screen.getByRole("button", { name: "Remove prompt 1" }));
    await user.press(screen.getByRole("button", { name: "Save prompts" }));
    expect(onSave).toHaveBeenCalledWith([]);
  });

  it("locks the fields while saving, so later typing isn't lost", async () => {
    const user = userEvent.setup();
    let finish = () => {};
    const onSave = jest.fn(() => new Promise<void>((resolve) => (finish = resolve)));
    await render(<PromptsEditor prompts={["Hi"]} custom onSave={onSave} onCancel={jest.fn()} />);

    await user.press(screen.getByRole("button", { name: "Save prompts" }));
    expect(screen.getByLabelText("Prompt 1").props.editable).toBe(false);
    await act(async () => finish());
    expect(screen.getByLabelText("Prompt 1").props.editable).toBe(true);
  });

  it("counts emoji as one character, like the server, and refuses past 200", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockResolvedValue(undefined);
    await render(<PromptsEditor prompts={["🚀".repeat(200)]} custom onSave={onSave} onCancel={jest.fn()} />);

    await user.press(screen.getByRole("button", { name: "Save prompts" }));
    expect(onSave).toHaveBeenCalledWith(["🚀".repeat(200)]);
    onSave.mockClear();
    await act(async () => fireEvent.changeText(screen.getByLabelText("Prompt 1"), "🚀".repeat(201)));
    await user.press(screen.getByRole("button", { name: "Save prompts" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/200 characters/);
    expect(onSave).not.toHaveBeenCalled();
  });

  it("shows the server's refusal and cancels", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockRejectedValue(new Error("Only this Bot's owner or an admin can do this."));
    const onCancel = jest.fn();
    await render(<PromptsEditor prompts={["Hi"]} custom onSave={onSave} onCancel={onCancel} />);

    await user.press(screen.getByRole("button", { name: "Save prompts" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/owner or an admin/);
    await user.press(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalled();
  });
});
