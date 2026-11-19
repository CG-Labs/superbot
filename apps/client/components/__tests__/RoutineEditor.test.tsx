import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { RoutineEditor } from "../RoutineEditor";
import type { Routine } from "../../src/types";

const routine: Routine = {
  id: "r1",
  bot_id: "b1",
  name: "Digest",
  cron: "0 9 * * *",
  instruction: "Sum up email",
  enabled: true,
};

describe("RoutineEditor", () => {
  it("creates a routine from a preset schedule", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockResolvedValue(undefined);
    await render(<RoutineEditor onSave={onSave} onCancel={jest.fn()} />);

    expect(screen.getByText("New routine")).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Delete routine" })).not.toBeOnTheScreen();
    await user.type(screen.getByLabelText("Routine name"), "Standup");
    await user.press(screen.getByRole("button", { name: "Weekdays 9:00" }));
    await user.type(screen.getByLabelText("Instruction"), "Post my standup notes");
    await user.press(screen.getByRole("button", { name: "Save routine" }));

    expect(onSave).toHaveBeenCalledWith({
      name: "Standup",
      cron: "0 9 * * 1-5",
      instruction: "Post my standup notes",
      enabled: true,
    });
  });

  it("shows validation errors instead of saving", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn();
    await render(<RoutineEditor onSave={onSave} onCancel={jest.fn()} />);

    await user.press(screen.getByRole("button", { name: "Save routine" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Name is required");
    expect(onSave).not.toHaveBeenCalled();
  });

  it("edits an existing routine and shows server errors", async () => {
    const user = userEvent.setup();
    const onSave = jest.fn().mockRejectedValue(new Error("Cron value out of range in \"99\""));
    await render(<RoutineEditor routine={routine} onSave={onSave} onDelete={jest.fn()} onCancel={jest.fn()} />);

    expect(screen.getByText("Edit routine")).toBeOnTheScreen();
    expect(screen.getByLabelText("Routine name")).toHaveDisplayValue("Digest");
    await user.clear(screen.getByLabelText("Cron schedule"));
    await user.type(screen.getByLabelText("Cron schedule"), "99 * * * *");
    await user.press(screen.getByRole("button", { name: "Save routine" }));

    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ cron: "99 * * * *", name: "Digest" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Cron value out of range/);
  });

  it("deletes and cancels", async () => {
    const user = userEvent.setup();
    const onDelete = jest.fn().mockResolvedValue(undefined);
    const onCancel = jest.fn();
    await render(<RoutineEditor routine={routine} onSave={jest.fn()} onDelete={onDelete} onCancel={onCancel} />);

    await user.press(screen.getByRole("button", { name: "Delete routine" }));
    expect(onDelete).toHaveBeenCalled();
    await user.press(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalled();
  });
});
