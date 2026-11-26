import React from "react";
import { fireEvent, render, screen, userEvent } from "@testing-library/react-native";
import { Divider, Field, Notice, PrimaryButton, SignInFrame, TextButton } from "../SignInParts";
import { themes } from "../../src/theme";

let mockWidth = 1280;
let mockScheme: "light" | "dark" | null = null;
jest.mock("react-native/Libraries/Utilities/useWindowDimensions", () => ({
  __esModule: true,
  default: () => ({ width: mockWidth, height: 900, scale: 2, fontScale: 1 }),
}));
jest.mock("react-native/Libraries/Utilities/useColorScheme", () => ({ __esModule: true, default: () => mockScheme }));

function windowOf(width: number) {
  mockWidth = width;
}

afterEach(() => {
  mockWidth = 1280;
  mockScheme = null;
});

describe("SignInFrame", () => {
  it("puts the steps in a raised card on wide windows", async () => {
    windowOf(1280);
    await render(
      <SignInFrame title="Welcome to SuperBot" subtitle="Connect to your self-hosted server">
        <Divider label="or" />
      </SignInFrame>,
    );
    expect(screen.getByRole("header")).toHaveTextContent("Welcome to SuperBot");
    expect(screen.getByText("Connect to your self-hosted server")).toBeOnTheScreen();
    expect(screen.getByTestId("sign-in-card")).toHaveStyle({ backgroundColor: themes.light.c.raised, borderRadius: themes.light.radius.xl });
  });

  it("drops the card's edge on a phone, so the screen is the card", async () => {
    windowOf(390);
    await render(<SignInFrame title="SuperBot is locked">{null}</SignInFrame>);
    expect(screen.getByTestId("sign-in-card")).not.toHaveStyle({ backgroundColor: themes.light.c.raised });
  });

  it.each(["light", "dark"] as const)("follows the device's %s setting", async (scheme) => {
    mockScheme = scheme;
    windowOf(1280);
    await render(<SignInFrame title="Welcome to SuperBot">{null}</SignInFrame>);
    expect(screen.getByTestId("sign-in-card")).toHaveStyle({ backgroundColor: themes[scheme].c.raised });
    expect(screen.getByRole("header")).toHaveStyle({ color: themes[scheme].c.text });
  });
});

describe("Field", () => {
  it("is named by its label and shows focus with the accent", async () => {
    const onFocus = jest.fn();
    await render(<Field label="Server URL" value="" onChangeText={() => {}} onFocus={onFocus} />);
    const input = screen.getByLabelText("Server URL");
    expect(input).toHaveStyle({ borderColor: themes.light.c.border });
    await fireEvent(input, "focus");
    expect(onFocus).toHaveBeenCalled();
    expect(screen.getByLabelText("Server URL")).toHaveStyle({ borderColor: themes.light.c.accent });
    await fireEvent(screen.getByLabelText("Server URL"), "blur");
    expect(screen.getByLabelText("Server URL")).toHaveStyle({ borderColor: themes.light.c.border });
  });
});

describe("buttons and notices", () => {
  it("fills the primary button with the accent, and holds it while busy", async () => {
    const onPress = jest.fn();
    const user = userEvent.setup();
    const { rerender } = await render(<PrimaryButton label="Connect" onPress={onPress} />);
    const button = screen.getByRole("button", { name: "Connect" });
    expect(button).toHaveStyle({ backgroundColor: themes.light.c.accent, borderRadius: themes.light.radius.pill });
    await user.press(button);
    expect(onPress).toHaveBeenCalledTimes(1);

    await rerender(<PrimaryButton label="Connect" onPress={onPress} busy />);
    expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
    expect(screen.queryByText("Connect")).not.toBeOnTheScreen();
  });

  it("disables a text button", async () => {
    await render(<TextButton label="Start over" onPress={() => {}} disabled />);
    expect(screen.getByRole("button", { name: "Start over" })).toBeDisabled();
  });

  it("announces a danger notice as an alert, and an info notice quietly", async () => {
    await render(
      <>
        <Notice tone="danger">That sign-in code has expired.</Notice>
        <Notice tone="info">Your invite code is filled in.</Notice>
      </>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("That sign-in code has expired.");
    expect(screen.getByText("That sign-in code has expired.")).toHaveStyle({ color: themes.light.c.danger });
    expect(screen.getByText("Your invite code is filled in.")).toHaveStyle({ color: themes.light.c.text });
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });
});
