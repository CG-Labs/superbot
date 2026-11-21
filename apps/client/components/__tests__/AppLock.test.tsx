import React from "react";
import { act, render, screen, userEvent, waitFor, within } from "@testing-library/react-native";
import { AppState, Text } from "react-native";
import { AppLockProvider, type LockStore } from "../AppLock";
import { AppLockCard } from "../SettingsView";
import { AUTH_FACE, serializeLockSettings, type DeviceProbe } from "../../src/appLock";
import type { LocalAuth } from "../../src/localAuth";

jest.setTimeout(20_000);

const mockCtx: { api: object | null; logout: jest.Mock } = { api: {}, logout: jest.fn() };
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));
jest.mock("expo-local-authentication", () => ({}));

const appState = AppState as unknown as { currentState: string; addEventListener: jest.Mock };
let listeners: ((s: string) => void)[] = [];

function fakeAuth(device: Partial<DeviceProbe> = {}, results: ({ success: true } | { success: false; error?: string })[] = []) {
  const probe: DeviceProbe = { hardware: true, enrolled: true, types: [AUTH_FACE], level: 3, ...device };
  return {
    device: probe,
    probe: jest.fn(async () => probe),
    authenticate: jest.fn(async () => results.shift() ?? { success: true as const }),
  } satisfies LocalAuth & { device: DeviceProbe };
}

function fakeStore(initial: string | null = null) {
  let value = initial;
  return {
    get value() {
      return value;
    },
    get: jest.fn(async () => value),
    set: jest.fn(async (v: string) => {
      value = v;
    }),
    clear: jest.fn(async () => {
      value = null;
    }),
  } satisfies LockStore & { value: string | null };
}

async function changeAppState(s: string) {
  await act(async () => {
    for (const l of listeners) l(s);
  });
}

async function show(props: { auth: LocalAuth; store: LockStore; os?: string; now?: () => number }) {
  return render(
    <AppLockProvider {...props} os={props.os ?? "ios"}>
      <Text>Chats</Text>
      <AppLockCard />
    </AppLockProvider>,
  );
}

beforeEach(() => {
  listeners = [];
  appState.currentState = "active";
  appState.addEventListener.mockImplementation((_: string, l: (s: string) => void) => {
    listeners.push(l);
    return { remove: () => (listeners = listeners.filter((x) => x !== l)) };
  });
  mockCtx.api = {};
  mockCtx.logout = jest.fn(async () => {
    mockCtx.api = null;
  });
});

describe("App lock (ADR 0078)", () => {
  it("is off by default: no lock, and turning it on asks for Face ID once", async () => {
    const auth = fakeAuth();
    const store = fakeStore();
    const user = userEvent.setup();
    await show({ auth, store });
    expect(await screen.findByText(/Ask for Face ID or your device passcode/)).toBeOnTheScreen();
    expect(screen.getByText("Chats")).toBeOnTheScreen();
    expect(screen.queryByText("SuperBot is locked")).toBeNull();
    expect(auth.authenticate).not.toHaveBeenCalled();

    await user.press(within(screen.getByLabelText("App lock on or off")).getByRole("radio", { name: "On" }));
    expect(await screen.findByText("App lock is on.")).toBeOnTheScreen();
    expect(auth.authenticate).toHaveBeenCalledWith("Turn on App lock");
    expect(store.value).toBe(serializeLockSettings({ enabled: true, lockAfter: 0 }));
    expect(screen.queryByText("SuperBot is locked")).toBeNull();

    await user.press(within(screen.getByLabelText("Lock after")).getByRole("radio", { name: "After 5 minutes" }));
    expect(await screen.findByText("Locks after 5 minutes.")).toBeOnTheScreen();
    expect(store.value).toBe(serializeLockSettings({ enabled: true, lockAfter: 300 }));

    await user.press(within(screen.getByLabelText("App lock on or off")).getByRole("radio", { name: "Off" }));
    expect(await screen.findByText("App lock is off.")).toBeOnTheScreen();
    expect(store.value).toBeNull();
  });

  it("stays off when the check to turn it on is cancelled", async () => {
    const auth = fakeAuth({}, [{ success: false, error: "user_cancel" }]);
    const store = fakeStore();
    const user = userEvent.setup();
    await show({ auth, store });
    await user.press(within(await screen.findByLabelText("App lock on or off")).getByRole("radio", { name: "On" }));
    expect(await screen.findByText("App lock stays off.")).toBeOnTheScreen();
    expect(store.set).not.toHaveBeenCalled();
  });

  it("locks on cold start and opens after Face ID", async () => {
    let finish: (r: { success: true }) => void = () => {};
    const auth = fakeAuth();
    auth.authenticate.mockImplementationOnce(() => new Promise((r) => (finish = r)));
    await show({ auth, store: fakeStore(serializeLockSettings({ enabled: true, lockAfter: 60 })) });
    expect(await screen.findByText("SuperBot is locked")).toBeOnTheScreen();
    await waitFor(() => expect(auth.authenticate).toHaveBeenCalledWith("Unlock SuperBot"));
    await act(async () => finish({ success: true }));
    expect(screen.queryByText("SuperBot is locked")).toBeNull();
    expect(screen.getByText("Chats")).toBeOnTheScreen();
  });

  it("asks again after a cancel only when Unlock is pressed", async () => {
    const auth = fakeAuth({}, [{ success: false, error: "user_cancel" }]);
    const user = userEvent.setup();
    await show({ auth, store: fakeStore(serializeLockSettings({ enabled: true, lockAfter: 0 })) });
    expect(await screen.findByText("Use Face ID or your passcode to open it.")).toBeOnTheScreen();
    expect(auth.authenticate).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByRole("button", { name: "Unlock" })).toBeEnabled());
    await user.press(screen.getByRole("button", { name: "Unlock" }));
    expect(auth.authenticate).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(screen.queryByText("SuperBot is locked")).toBeNull());
  });

  it("hides content while inactive and locks after the timeout in the background", async () => {
    let clock = 0;
    const auth = fakeAuth({}, [{ success: true }, { success: false, error: "user_cancel" }]);
    await show({ auth, store: fakeStore(serializeLockSettings({ enabled: true, lockAfter: 60 })), now: () => clock });
    await waitFor(() => expect(screen.queryByText("SuperBot is locked")).toBeNull());
    await waitFor(() => expect(auth.authenticate).toHaveBeenCalledTimes(1));
    await act(async () => {});

    await changeAppState("inactive");
    expect(screen.getByTestId("app-lock-cover")).toBeOnTheScreen();
    await changeAppState("active");
    expect(screen.queryByTestId("app-lock-cover")).toBeNull();

    await changeAppState("background");
    clock = 30_000;
    await changeAppState("active");
    expect(screen.queryByText("SuperBot is locked")).toBeNull();

    await changeAppState("background");
    clock = 100_000;
    await changeAppState("active");
    expect(await screen.findByText("SuperBot is locked")).toBeOnTheScreen();
  });

  it("ignores the app leaving the foreground for its own prompt", async () => {
    let finish: (r: { success: true }) => void = () => {};
    const auth = fakeAuth();
    auth.authenticate.mockImplementationOnce(() => new Promise((r) => (finish = r)));
    await show({ auth, store: fakeStore(serializeLockSettings({ enabled: true, lockAfter: 0 })) });
    expect(await screen.findByText("SuperBot is locked")).toBeOnTheScreen();
    await waitFor(() => expect(auth.authenticate).toHaveBeenCalledTimes(1));
    await changeAppState("background");
    await changeAppState("active");
    await act(async () => finish({ success: true }));
    expect(screen.queryByText("SuperBot is locked")).toBeNull();
    expect(auth.authenticate).toHaveBeenCalledTimes(1);
  });

  it("can't be turned on without enrolled biometrics", async () => {
    await show({ auth: fakeAuth({ enrolled: false }), store: fakeStore() });
    expect(await screen.findByText("Set up Face ID in your device's settings first, then come back to turn on App lock.")).toBeOnTheScreen();
    expect(within(screen.getByLabelText("App lock on or off")).getByRole("radio", { name: "On" })).toBeDisabled();
  });

  it("can't be turned on without a sensor", async () => {
    await show({ auth: fakeAuth({ hardware: false, enrolled: false, types: [] }), store: fakeStore() });
    expect(await screen.findByText(/no Face ID, Touch ID or fingerprint sensor/)).toBeOnTheScreen();
    expect(within(screen.getByLabelText("App lock on or off")).getByRole("radio", { name: "On" })).toBeDisabled();
  });

  it("is unavailable on web, and never locks or probes there", async () => {
    const auth = fakeAuth();
    const store = fakeStore(serializeLockSettings({ enabled: true, lockAfter: 0 }));
    await show({ auth, store, os: "web" });
    expect(await screen.findByText(/isn't available in the browser/)).toBeOnTheScreen();
    expect(screen.queryByText("SuperBot is locked")).toBeNull();
    expect(screen.queryByLabelText("App lock on or off")).toBeNull();
    await changeAppState("background");
    await changeAppState("active");
    expect(screen.getByText("Chats")).toBeOnTheScreen();
    expect(auth.probe).not.toHaveBeenCalled();
    expect(store.get).not.toHaveBeenCalled();
  });

  it("fails safe when the device can't check it's you any more: sign out, and the lock turns off", async () => {
    const auth = fakeAuth({ hardware: false, enrolled: false, types: [], level: 0 });
    const store = fakeStore(serializeLockSettings({ enabled: true, lockAfter: 0 }));
    const user = userEvent.setup();
    const view = await show({ auth, store });
    expect(await screen.findByText(/no longer has Face ID, a fingerprint or a passcode set up/)).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Unlock" })).toBeNull();
    expect(auth.authenticate).not.toHaveBeenCalled();

    await user.press(screen.getByRole("button", { name: "Sign out" }));
    expect(mockCtx.logout).toHaveBeenCalled();
    await view.rerender(
      <AppLockProvider auth={auth} store={store} os="ios">
        <Text>Sign in</Text>
      </AppLockProvider>,
    );
    await waitFor(() => expect(store.value).toBeNull());
    expect(screen.queryByText("SuperBot is locked")).toBeNull();
  });

  it("fails safe when the prompt says biometrics were removed", async () => {
    const auth = fakeAuth({ enrolled: false, level: 1 }, [{ success: false, error: "passcode_not_set" }]);
    await show({ auth, store: fakeStore(serializeLockSettings({ enabled: true, lockAfter: 0 })) });
    expect(await screen.findByText(/Sign out to continue/)).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Unlock" })).toBeNull();
  });

  it("turns off when you sign out anywhere else", async () => {
    const store = fakeStore(serializeLockSettings({ enabled: true, lockAfter: 60 }));
    const auth = fakeAuth();
    const view = await show({ auth, store });
    await waitFor(() => expect(screen.queryByText("SuperBot is locked")).toBeNull());
    mockCtx.api = null;
    await view.rerender(
      <AppLockProvider auth={auth} store={store} os="ios">
        <Text>Sign in</Text>
      </AppLockProvider>,
    );
    await waitFor(() => expect(store.value).toBeNull());
  });

  it("doesn't lock a signed-out app", async () => {
    mockCtx.api = null;
    await show({ auth: fakeAuth(), store: fakeStore(serializeLockSettings({ enabled: true, lockAfter: 0 })) });
    await act(async () => {});
    expect(screen.queryByText("SuperBot is locked")).toBeNull();
  });
});
