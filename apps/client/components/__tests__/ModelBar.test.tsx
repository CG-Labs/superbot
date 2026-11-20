import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { ModelBar, PlanBar } from "../ModelBar";

const mockCtx = {
  fetchModels: jest.fn(),
  patchBot: jest.fn().mockResolvedValue(undefined),
};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

it("lets the user type a model when the harness takes any model name", async () => {
  const user = userEvent.setup();
  mockCtx.fetchModels.mockResolvedValue([
    { id: "", label: "Default model", efforts: ["low", "high"] },
  ]);
  await render(<ModelBar botId="b1" harness="hermes" />);

  const field = await screen.findByLabelText("Model");
  await user.type(field, "anthropic/claude-sonnet-4");
  await user.type(field, "{Enter}", { submitEditing: true });
  expect(mockCtx.patchBot).toHaveBeenCalledWith(
    "b1",
    expect.objectContaining({ model: "anthropic/claude-sonnet-4" }),
  );
});

it("doesn't carry typed text to another Bot", async () => {
  const user = userEvent.setup();
  mockCtx.fetchModels.mockResolvedValue([
    { id: "", label: "Default model", efforts: [] },
  ]);
  const view = await render(<ModelBar botId="b1" harness="hermes" />);
  await user.type(await screen.findByLabelText("Model"), "half-typed");

  await view.rerender(<ModelBar botId="b2" harness="hermes" />);
  const field = screen.getByLabelText("Model");
  expect(field.props.value).toBe("");
  await user.type(field, "{Enter}", { submitEditing: true });
  expect(mockCtx.patchBot).not.toHaveBeenCalledWith("b2", expect.anything());
});

it("asks only for the plan's models when the Bot is on a managed plan", async () => {
  mockCtx.fetchModels.mockResolvedValue([{ id: "claude-sonnet-4-5", label: "Sonnet", efforts: [] }]);
  await render(<ModelBar botId="b1" harness="claude" tier="pro" />);
  expect(mockCtx.fetchModels).toHaveBeenLastCalledWith("claude", "pro");
});

it("names the plan, not a model", async () => {
  await render(<PlanBar label="Pro" />);
  expect(screen.getByLabelText("Plan")).toHaveTextContent("Pro plan · the plan picks the model");
});
