import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { HandoffBanner } from "../HandoffBanner";
import type { Message } from "../../src/types";

const handoff: Message = {
  id: 3,
  botId: "b1",
  role: "bot",
  text: "",
  question: { title: "Solve the CAPTCHA", options: ["Done", "I can't right now"], handoff: true },
  at: 1,
};

it("tells the user what the Bot needs and opens its screen", async () => {
  const user = userEvent.setup();
  const onOpenScreen = jest.fn();
  await render(<HandoffBanner botName="Ada" handoff={handoff} onOpenScreen={onOpenScreen} />);

  expect(screen.getByText(/Ada needs you on its screen/)).toBeOnTheScreen();
  expect(screen.getByText("Solve the CAPTCHA")).toBeOnTheScreen();
  await user.press(screen.getByRole("button", { name: "Open screen" }));
  expect(onOpenScreen).toHaveBeenCalled();
});
