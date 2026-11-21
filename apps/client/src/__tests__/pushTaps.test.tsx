import { renderHook } from "@testing-library/react-native";
import { usePushTaps } from "../pushTaps";
import type { PushDevice } from "../pushDevice";

jest.mock("expo-notifications", () => ({}));
jest.mock("expo-constants", () => ({}));
jest.mock("expo-router", () => ({ router: { push: jest.fn() } }));

it("opens what a tapped push links to, and nothing else", async () => {
  let tap: (data: unknown) => void = () => {};
  const unsubscribe = jest.fn();
  const device = {
    platform: "android",
    projectId: null,
    permission: jest.fn(),
    requestPermission: jest.fn(),
    token: jest.fn(),
    onTap: jest.fn((cb: (data: unknown) => void) => {
      tap = cb;
      return unsubscribe;
    }),
  } as unknown as PushDevice;
  const go = jest.fn();
  const { unmount } = await renderHook(() => usePushTaps(device, go));

  tap({ type: "approval", approvalId: "ap1" });
  tap({ type: "routine", botId: "b1" });
  tap({ url: "https://example.com" });
  expect(go.mock.calls).toEqual([[{ pathname: "/home", params: { approval: "ap1" } }], [{ pathname: "/home", params: { bot: "b1" } }]]);

  await unmount();
  expect(unsubscribe).toHaveBeenCalled();
});
