import React from "react";
import * as RN from "react-native";
import { fireEvent, render, screen } from "@testing-library/react-native";
import { themes, ThemeScope } from "../../src/theme";
import { Chips } from "../Chips";
import { Card, kit, PageHeader } from "../ui";

afterEach(() => jest.restoreAllMocks());

describe("PageHeader", () => {
  it("shows the title as a header and goes back", async () => {
    const onBack = jest.fn();
    await render(<PageHeader title="Settings" onBack={onBack} right={<RN.Text>Extra</RN.Text>} />);
    expect(screen.getByRole("header", { name: "Settings" })).toBeOnTheScreen();
    expect(screen.getByText("‹ Bots")).toBeOnTheScreen();
    expect(screen.getByText("Extra")).toBeOnTheScreen();
    fireEvent.press(screen.getByRole("button", { name: "Back to Bots" }));
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it("takes its own back text and label, and has no back button without onBack", async () => {
    const onBack = jest.fn();
    const { rerender } = await render(<PageHeader title="Rule" onBack={onBack} backText="‹ Back" backLabel="Back" />);
    expect(screen.getByRole("button", { name: "Back" })).toHaveTextContent("‹ Back");
    await rerender(<PageHeader title="Rule" />);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("holds the back button while asked to", async () => {
    const onBack = jest.fn();
    await render(<PageHeader title="Service accounts" onBack={onBack} backDisabled />);
    const back = screen.getByRole("button", { name: "Back to Bots" });
    expect(back).toBeDisabled();
    fireEvent.press(back);
    expect(onBack).not.toHaveBeenCalled();
  });
});

describe("the settings kit", () => {
  it.each(["light", "dark"] as const)("takes the %s palette from the device setting", async (scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(scheme);
    await render(<Card title="App lock" testID="card" />);
    expect(screen.getByTestId("card")).toHaveStyle({ backgroundColor: themes[scheme].c.raised, borderRadius: themes[scheme].radius.lg });
    expect(screen.getByText("App lock")).toHaveStyle({ color: themes[scheme].c.text });
  });

  it("makes each scheme's styles once", () => {
    expect(kit(themes.light)).toBe(kit(themes.light));
    expect(kit(themes.light)).not.toBe(kit(themes.dark));
    expect(kit(themes.dark).primary).toMatchObject({ backgroundColor: themes.dark.c.accent });
  });
});

describe("Chips", () => {
  const options = [
    { value: "on", label: "On" },
    { value: "off", label: "Off" },
  ] as const;

  it("fills the picked choice with the text colour and reports it checked", async () => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue("light");
    const onChange = jest.fn();
    await render(<Chips options={options} value="on" onChange={onChange} />);
    const on = screen.getByRole("radio", { name: "On" });
    expect(on).toBeChecked();
    expect(on).toHaveStyle({ backgroundColor: themes.light.c.text });
    expect(screen.getByRole("radio", { name: "Off" })).toHaveStyle({ backgroundColor: themes.light.c.raised });
    fireEvent.press(screen.getByRole("radio", { name: "Off" }));
    expect(onChange).toHaveBeenCalledWith("off");
  });

  it("stays dark inside a dark scope, for screens not yet restyled", async () => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue("light");
    await render(
      <ThemeScope scheme="dark">
        <Chips options={options} value="on" onChange={() => {}} />
      </ThemeScope>,
    );
    expect(screen.getByRole("radio", { name: "On" })).toHaveStyle({ backgroundColor: themes.dark.c.text });
  });
});
