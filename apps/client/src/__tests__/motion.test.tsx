import { AccessibilityInfo, Platform } from "react-native";
import { act, renderHook } from "@testing-library/react-native";
import { useMotionPreference, useReducedMotion } from "../motion";

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

  it("holds motion back while the device's setting is still on its way", async () => {
    let answer: (on: boolean) => void = () => {};
    jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockReturnValue(new Promise((resolve) => (answer = resolve)));
    const pref = await renderHook(() => useMotionPreference());
    const { result } = await renderHook(() => useReducedMotion());
    expect(pref.result.current).toBeNull();
    expect(result.current).toBe(true);

    await act(async () => answer(false));
    expect(result.current).toBe(false);
  });

  it("allows motion when the setting can't be read", async () => {
    jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockRejectedValue(new Error("unavailable"));
    const { result } = await renderHook(() => useReducedMotion());
    await act(async () => {});
    expect(result.current).toBe(false);
  });

  it.each([true, false])("on web, reads prefers-reduced-motion (%s) on the first render", async (matches) => {
    jest.replaceProperty(Platform, "OS", "web");
    Object.defineProperty(globalThis, "matchMedia", { value: jest.fn(() => ({ matches })), configurable: true, writable: true });
    jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockReturnValue(new Promise(() => {}));
    try {
      const { result } = await renderHook(() => useReducedMotion());
      expect(result.current).toBe(matches);
    } finally {
      delete (globalThis as { matchMedia?: unknown }).matchMedia;
    }
  });
});
