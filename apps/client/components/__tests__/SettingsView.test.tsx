import React from "react";
import { act, render, screen, userEvent, within } from "@testing-library/react-native";
import { AppLockProvider, type LockStore } from "../AppLock";
import { SettingsView } from "../SettingsView";
import { AUTH_FACE, type DeviceProbe } from "../../src/appLock";

jest.setTimeout(20_000);

jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => ({ api: {}, logout: jest.fn() }) }));
jest.mock("expo-local-authentication", () => ({}));

const PROBE: DeviceProbe = { hardware: true, enrolled: true, types: [AUTH_FACE], level: 3 };

function fakeStore(): LockStore {
  let value: string | null = null;
  return {
    get: jest.fn(async () => value),
    set: jest.fn(async (v: string) => {
      value = v;
    }),
    clear: jest.fn(async () => {
      value = null;
    }),
  };
}

describe("SettingsView", () => {
  it("titles its sections and shows a skeleton while it checks the device", async () => {
    let probed: (p: DeviceProbe) => void = () => {};
    const auth = { probe: jest.fn(() => new Promise<DeviceProbe>((r) => (probed = r))), authenticate: jest.fn(async () => ({ success: true as const })) };
    await render(
      <AppLockProvider auth={auth} store={fakeStore()} os="ios">
        <SettingsView onBack={jest.fn()} />
      </AppLockProvider>,
    );
    expect(screen.getByRole("heading", { name: "This device" })).toBeOnTheScreen();
    expect(screen.getByRole("heading", { name: "App lock" })).toBeOnTheScreen();
    expect(screen.getByRole("progressbar", { name: "Loading App lock" })).toBeOnTheScreen();
    await act(async () => probed(PROBE));
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.getByText(/Ask for Face ID or your device passcode/)).toBeOnTheScreen();
    expect(screen.queryByRole("heading", { name: "Your account" })).toBeNull();
  });

  it("says why App lock couldn't be saved, without a retry", async () => {
    const auth = { probe: jest.fn(async () => PROBE), authenticate: jest.fn(async () => ({ success: true as const })) };
    const store = fakeStore();
    (store.set as jest.Mock).mockRejectedValueOnce(new Error("Keychain unavailable"));
    const user = userEvent.setup();
    await render(
      <AppLockProvider auth={auth} store={store} os="ios">
        <SettingsView onBack={jest.fn()} />
      </AppLockProvider>,
    );
    await user.press(within(await screen.findByLabelText("App lock on or off")).getByRole("radio", { name: "On" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Keychain unavailable");
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });
});
