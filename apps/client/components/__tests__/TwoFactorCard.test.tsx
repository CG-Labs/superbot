import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { proofFrom, TwoFactorCard, type MfaApi } from "../TwoFactor";
import { themes } from "../../src/theme";
import type { MfaStatus } from "../../src/types";

let mockScheme: "light" | "dark" | null = null;
jest.mock("react-native/Libraries/Utilities/useColorScheme", () => ({ __esModule: true, default: () => mockScheme }));
jest.mock("../../src/dialogs", () => ({ confirmAsync: jest.fn(async () => true) }));

const off: MfaStatus = { enabled: false, enabledAt: null, pending: false, recoveryCodesLeft: 0, required: false, policy: "off", policyPinned: false };
const on: MfaStatus = { ...off, enabled: true, enabledAt: 1, recoveryCodesLeft: 10 };

function fakeApi(start: MfaStatus): jest.Mocked<MfaApi> {
  return {
    mfaStatus: jest.fn(async () => start),
    mfaEnroll: jest.fn(async () => ({ secret: "JBSWY3DPEHPK3PXP", otpauthUrl: "otpauth://totp/x", qrSvg: "" })),
    mfaConfirm: jest.fn(async () => ({ ...on, recoveryCodes: ["aaaaa-bbbbb"] })),
    mfaNewRecoveryCodes: jest.fn(async () => ({ ...on, recoveryCodes: ["ccccc-ddddd"] })),
    mfaDisable: jest.fn(async () => off),
    setMfaPolicy: jest.fn(async (p) => ({ ...start, policy: p })),
  } as unknown as jest.Mocked<MfaApi>;
}

describe("TwoFactorCard", () => {
  it("tells codes from the app and recovery codes apart", () => {
    expect(proofFrom(" 123 456 ")).toEqual({ totp: "123456" });
    expect(proofFrom("abcde-fghij")).toEqual({ recoveryCode: "abcde-fghij" });
    expect(proofFrom("  ")).toBeNull();
  });

  it("turns it on with a code and shows the recovery codes once", async () => {
    const api = fakeApi(off);
    const user = userEvent.setup();
    await render(<TwoFactorCard api={api} />);
    expect(await screen.findByText("Off.")).toBeOnTheScreen();
    await user.press(screen.getByText("Turn on"));
    expect(await screen.findByTestId("mfa-key")).toHaveTextContent("JBSW Y3DP EHPK 3PXP");
    await user.type(screen.getByLabelText("Code from your authenticator app"), "123456");
    await user.press(screen.getByText("Turn on"));
    expect(api.mfaConfirm).toHaveBeenCalledWith("123456");
    expect(await screen.findByText("aaaaa-bbbbb")).toBeOnTheScreen();
    await user.press(screen.getByText("I saved them"));
    expect(screen.getByTestId("mfa-state")).toHaveTextContent("On, with 10 recovery codes left.");
    expect(screen.queryByText("Required for")).not.toBeOnTheScreen();
  });

  it.each(["light", "dark"] as const)("shows the recovery codes in the card's %s theme", async (scheme) => {
    mockScheme = scheme;
    const user = userEvent.setup();
    await render(<TwoFactorCard api={fakeApi(on)} />);
    await user.press(await screen.findByText("New recovery codes"));
    await user.type(screen.getByLabelText("Code or recovery code"), "654321");
    await user.press(screen.getByText("Make new codes"));
    expect(await screen.findByText("ccccc-ddddd")).toHaveStyle({ color: themes[scheme].c.text });
    mockScheme = null;
  });

  it("needs a code to turn it off, and hides that when it's required", async () => {
    const api = fakeApi(on);
    const user = userEvent.setup();
    await render(<TwoFactorCard api={api} />);
    await user.press(await screen.findByText("Turn off"));
    await user.type(screen.getByLabelText("Code or recovery code"), "654321");
    await user.press(screen.getAllByText("Turn off").at(-1)!);
    expect(api.mfaDisable).toHaveBeenCalledWith({ totp: "654321" });
    expect(await screen.findByText("Off.")).toBeOnTheScreen();

    await render(<TwoFactorCard api={fakeApi({ ...on, required: true })} />);
    expect(await screen.findByText("New recovery codes")).toBeOnTheScreen();
    expect(screen.queryByText("Turn off")).not.toBeOnTheScreen();
  });

  it("lets admins set the policy unless the server pins it", async () => {
    const api = fakeApi(off);
    const user = userEvent.setup();
    await render(<TwoFactorCard api={api} admin />);
    await user.press(await screen.findByText("Admins"));
    expect(api.setMfaPolicy).toHaveBeenCalledWith("admins");

    await render(<TwoFactorCard api={fakeApi({ ...off, policyPinned: true })} admin />);
    expect(await screen.findByText("Set by AUTH_MFA on the server.")).toBeOnTheScreen();
  });
});
