import React from "react";
import { act, render, screen, userEvent } from "@testing-library/react-native";
import { ScreenViewer } from "../ScreenViewer";
import type { Message } from "../../src/types";

jest.mock("../ScreenFrame", () => ({
  ScreenFrame: ({ url }: { url: string }) => {
    const { Text: MockText } = jest.requireActual("react-native");
    return <MockText testID="screen-frame">{url}</MockText>;
  },
}));

const handoff: Message = {
  id: 9,
  botId: "b1",
  role: "bot",
  text: "",
  question: { title: "Enter the 2FA code", options: ["Done", "I can't right now"], handoff: true },
  at: 1,
};

describe("ScreenViewer", () => {
  it("shows the live view read-only until the user takes over", async () => {
    const user = userEvent.setup();
    const fetchUrl = jest.fn().mockResolvedValue("https://bots.example.com/screen/6901/?token=t");
    await render(<ScreenViewer botId="b1" botName="Ada" fetchUrl={fetchUrl} onClose={jest.fn()} />);

    expect(await screen.findByTestId("screen-frame")).toHaveTextContent("https://bots.example.com/screen/6901/?token=t");
    expect(fetchUrl).toHaveBeenCalledWith("b1");
    expect(screen.getByText("Ada's screen")).toBeOnTheScreen();
    expect(screen.getByTestId("screen-shield")).toBeOnTheScreen();

    await user.press(screen.getByRole("button", { name: "Take over" }));
    expect(screen.queryByTestId("screen-shield")).not.toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Give back" }));
    expect(screen.getByTestId("screen-shield")).toBeOnTheScreen();
  });

  it("shows the server's error when screens are off", async () => {
    const fetchUrl = jest.fn().mockRejectedValue(new Error("Screens are off on this server."));
    await render(<ScreenViewer botId="b1" botName="Ada" fetchUrl={fetchUrl} onClose={jest.fn()} />);

    expect(await screen.findByText("Screens are off on this server.")).toBeOnTheScreen();
    expect(screen.queryByTestId("screen-frame")).not.toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Take over" })).toBeDisabled();
  });

  it("keeps the screen alive and drops control when the link changes", async () => {
    jest.useFakeTimers();
    try {
      const fetchUrl = jest
        .fn()
        .mockResolvedValueOnce("https://h/screen/6901/?token=a")
        .mockResolvedValueOnce("https://h/screen/6901/?token=a")
        .mockResolvedValueOnce("https://h/screen/6902/?token=b");
      await render(
        <ScreenViewer botId="b1" botName="Ada" fetchUrl={fetchUrl} onClose={jest.fn()} initialControl refreshMs={1000} />,
      );
      expect(await screen.findByTestId("screen-frame")).toHaveTextContent(/token=a/);
      expect(screen.queryByTestId("screen-shield")).not.toBeOnTheScreen();

      await act(async () => {
        await jest.advanceTimersByTimeAsync(1000);
      });
      expect(fetchUrl).toHaveBeenCalledTimes(2);
      expect(screen.queryByTestId("screen-shield")).not.toBeOnTheScreen();

      await act(async () => {
        await jest.advanceTimersByTimeAsync(1000);
      });
      expect(fetchUrl).toHaveBeenCalledTimes(3);
      expect(screen.getByTestId("screen-frame")).toHaveTextContent(/token=b/);
      expect(screen.getByTestId("screen-shield")).toBeOnTheScreen();
    } finally {
      jest.useRealTimers();
    }
  });

  it("hands the screen back with Done during a handoff", async () => {
    const user = userEvent.setup();
    const onHandoffDone = jest.fn().mockResolvedValue(undefined);
    const onClose = jest.fn();
    await render(
      <ScreenViewer
        botId="b1"
        botName="Ada"
        fetchUrl={jest.fn().mockResolvedValue("https://h/screen/6901/?token=a")}
        onClose={onClose}
        initialControl
        handoff={handoff}
        onHandoffDone={onHandoffDone}
      />,
    );
    await screen.findByTestId("screen-frame");
    expect(screen.getByText("Ada needs you: Enter the 2FA code")).toBeOnTheScreen();
    expect(screen.queryByTestId("screen-shield")).not.toBeOnTheScreen();

    await user.press(screen.getByRole("button", { name: "Done, hand back to Bot" }));
    expect(onHandoffDone).toHaveBeenCalled();
    expect(await screen.findByTestId("screen-shield")).toBeOnTheScreen();

    await user.press(screen.getByRole("button", { name: "Close screen" }));
    expect(onClose).toHaveBeenCalled();
  });

  it("has no Done button without a handoff", async () => {
    await render(
      <ScreenViewer botId="b1" botName="Ada" fetchUrl={jest.fn().mockResolvedValue("https://h/screen/1/")} onClose={jest.fn()} />,
    );
    await screen.findByTestId("screen-frame");
    expect(screen.queryByRole("button", { name: "Done, hand back to Bot" })).not.toBeOnTheScreen();
  });
});
