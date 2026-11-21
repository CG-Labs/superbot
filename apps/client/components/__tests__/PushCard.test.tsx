import React from "react";
import { render, screen, userEvent, waitFor, within } from "@testing-library/react-native";
import { PushCard, type PushApi } from "../PushCard";
import type { PushDevice } from "../../src/pushDevice";
import type { PushRegistration, PushView } from "../../src/types";

jest.setTimeout(20_000);
jest.mock("expo-notifications", () => ({}));
jest.mock("expo-constants", () => ({}));

const PROJECT = "2b5b6a52-8f8e-4c4a-9d7e-6f1c0a9b3e21";
const TOKEN = "ExponentPushToken[abc]";

function fakeDevice(over: Partial<PushDevice> = {}, permission: "granted" | "denied" | "undetermined" = "undetermined", asked: "granted" | "denied" = "granted") {
  return {
    platform: "ios" as const,
    projectId: PROJECT,
    permission: jest.fn(async () => permission),
    requestPermission: jest.fn(async () => asked),
    token: jest.fn(async () => TOKEN),
    onTap: jest.fn(() => () => {}),
    ...over,
  } satisfies PushDevice;
}

function fakeApi(view: PushView) {
  let current = view;
  return {
    pushDevice: jest.fn(async () => current),
    registerPush: jest.fn(async (b: PushRegistration) => {
      current = {
        ...current,
        device: { id: "pd1", platform: b.platform, approvals: b.approvals ?? true, routines: b.routines ?? true, createdAt: 1, updatedAt: 2 },
      };
      return current;
    }),
    unregisterPush: jest.fn(async () => {
      current = { ...current, device: null };
      return current;
    }),
  } satisfies PushApi;
}

const ON: PushView = { available: true, provider: "expo", device: null };

function chip(group: string, label: string) {
  return within(screen.getByLabelText(group)).getByText(label);
}

it("is a no-op on the web and in the desktop app", async () => {
  const api = fakeApi(ON);
  await render(<PushCard api={api} device={fakeDevice({ platform: null })} />);
  expect(screen.getByText(/iPhone and Android apps/)).toBeTruthy();
  expect(api.pushDevice).not.toHaveBeenCalled();
});

it("says when the server has push off", async () => {
  await render(<PushCard api={fakeApi({ available: false, provider: null, device: null })} device={fakeDevice()} />);
  expect(await screen.findByText(/PUSH_PROVIDER=expo/)).toBeTruthy();
  expect(screen.queryByLabelText("Push notifications on or off")).toBeNull();
});

it("asks the phone only when you turn it on, then registers this phone", async () => {
  const user = userEvent.setup();
  const api = fakeApi(ON);
  const device = fakeDevice();
  await render(<PushCard api={api} device={device} />);
  await screen.findByLabelText("Push notifications on or off");
  expect(device.requestPermission).not.toHaveBeenCalled();

  await user.press(chip("Push notifications on or off", "On"));
  expect(await screen.findByText("Push notifications are on for this phone.")).toBeTruthy();
  expect(device.requestPermission).toHaveBeenCalledTimes(1);
  expect(api.registerPush).toHaveBeenCalledWith({ token: TOKEN, platform: "ios", approvals: true, routines: true });
  expect(screen.getByLabelText("Approvals")).toBeTruthy();

  await user.press(chip("Routines", "Off"));
  await waitFor(() => expect(api.registerPush).toHaveBeenLastCalledWith({ token: TOKEN, platform: "ios", approvals: true, routines: false }));

  await user.press(chip("Push notifications on or off", "Off"));
  expect(await screen.findByText("Push notifications are off for this phone.")).toBeTruthy();
  expect(api.unregisterPush).toHaveBeenCalledTimes(1);
  expect(screen.queryByLabelText("Approvals")).toBeNull();
});

it("registers nothing when the phone blocks notifications", async () => {
  const user = userEvent.setup();
  const api = fakeApi(ON);
  await render(<PushCard api={api} device={fakeDevice({}, "undetermined", "denied")} />);
  await user.press(await screen.findByText("On"));
  expect(await screen.findByText(/blocked for SuperBot/)).toBeTruthy();
  expect(api.registerPush).not.toHaveBeenCalled();
});

it("says so when the build has no push project", async () => {
  const user = userEvent.setup();
  const api = fakeApi(ON);
  const device = fakeDevice({ projectId: "00000000-0000-4000-8000-000000000001" });
  await render(<PushCard api={api} device={device} />);
  await user.press(await screen.findByText("On"));
  expect(await screen.findByText(/no Expo project/)).toBeTruthy();
  expect(device.requestPermission).not.toHaveBeenCalled();
  expect(api.registerPush).not.toHaveBeenCalled();
});

it("shows the server's reason, like a session that can't have a phone", async () => {
  const api = fakeApi(ON);
  api.pushDevice.mockRejectedValueOnce(new Error("Push notifications need a signed-in session."));
  await render(<PushCard api={api} device={fakeDevice()} />);
  expect(await screen.findByText(/need a signed-in session/)).toBeTruthy();
});

it("still lets you remove a saved phone while the server has push paused", async () => {
  const user = userEvent.setup();
  const api = fakeApi({ available: false, provider: null, device: { id: "pd1", platform: "ios", approvals: true, routines: true, createdAt: 1, updatedAt: 2 } });
  await render(<PushCard api={api} device={fakeDevice()} />);
  expect(await screen.findByText(/still saved/)).toBeTruthy();
  expect(screen.queryByLabelText("Approvals")).toBeNull();
  await user.press(chip("Push notifications on or off", "Off"));
  expect(await screen.findByText("Push notifications are off for this phone.")).toBeTruthy();
  expect(api.unregisterPush).toHaveBeenCalledTimes(1);
  expect(screen.queryByLabelText("Push notifications on or off")).toBeNull();
});
