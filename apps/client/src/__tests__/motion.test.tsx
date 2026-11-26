import { AccessibilityInfo } from "react-native";
import { act, renderHook } from "@testing-library/react-native";
import { useReducedMotion } from "../motion";

describe("useReducedMotion", () => {
  afterEach(() => jest.restoreAllMocks());

  it("follows the device's setting and its changes", async () => {
    let listener: ((on: boolean) => void) | undefined;
    const remove = jest.fn();
    jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockResolvedValue(true);
    jest.spyOn(AccessibilityInfo, "addEventListener").mockImplementation(((_: string, fn: (on: boolean) => void) => {
      listener = fn;
      return { remove };
    }) as never);

    const { result, unmount } = await renderHook(() => useReducedMotion());
    await act(async () => {});
    expect(result.current).toBe(true);

    await act(async () => listener?.(false));
    expect(result.current).toBe(false);

    await unmount();
    expect(remove).toHaveBeenCalled();
  });
});
