import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { ModelBar } from "../ModelBar";

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
