import React from "react";
import * as RN from "react-native";
import { act, fireEvent, render, renderHook, screen } from "@testing-library/react-native";
import { themes } from "../../src/theme";
import { DetailSheet, goBack, PaneTransition, RouteNotice, RouteScreen, stackOptions, statusBarStyle, useGoBack, useModalAnimation, useMotion } from "../Shell";
import { PageHeader } from "../ui";

const mockRouter = { canGoBack: jest.fn(() => false), back: jest.fn(), replace: jest.fn() };
jest.mock("expo-router", () => ({
  get router() {
    return mockRouter;
  },
}));

const { AccessibilityInfo, Animated } = RN;

const flat = (testID: string) => RN.StyleSheet.flatten(screen.getByTestId(testID).props.style) ?? {};

/** Makes the device ask for less motion, or not. */
function reduceMotion(on: boolean) {
  jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockResolvedValue(on);
}

beforeEach(() => {
  mockRouter.canGoBack.mockReturnValue(false);
  mockRouter.back.mockClear();
  mockRouter.replace.mockClear();
});
afterEach(() => jest.restoreAllMocks());

describe("PageHeader", () => {
  it.each(["light", "dark"] as const)("sits on the %s canvas with the title in body text", async (scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(scheme);
    const t = themes[scheme];
    await render(<PageHeader title="Settings" subtitle="This device" onBack={() => {}} />);
    const title = screen.getByRole("header", { name: "Settings" });
    expect(title).toHaveStyle({ color: t.c.text });
    expect(screen.getByText("This device")).toHaveStyle({ color: t.c.textMuted });
    expect(screen.getByText("‹ Bots")).toHaveStyle({ color: t.c.text });
  });

  it("gives the back pill room to tap, and leaves the title out when there is none", async () => {
    await render(<PageHeader onBack={() => {}} backText="‹ Users" backLabel="Back to users" />);
    expect(screen.getByRole("button", { name: "Back to users" }).props.hitSlop).toBe(8);
    expect(screen.queryByRole("header")).toBeNull();
  });
});

describe("going back", () => {
  it("goes back a screen when there is one", async () => {
    mockRouter.canGoBack.mockReturnValue(true);
    const { result } = await renderHook(() => useGoBack());
    result.current();
    expect(mockRouter.back).toHaveBeenCalledTimes(1);
    expect(mockRouter.replace).not.toHaveBeenCalled();
  });

  it("goes home after a link or a reload, when there is nothing to go back to", () => {
    goBack();
    expect(mockRouter.replace).toHaveBeenCalledWith("/home");
    goBack("/settings");
    expect(mockRouter.replace).toHaveBeenLastCalledWith("/settings");
    expect(mockRouter.back).not.toHaveBeenCalled();
  });
});

describe("RouteNotice", () => {
  it("keeps the screen's header and both ways back", async () => {
    const onBack = jest.fn();
    await render(<RouteNotice title="Users" message="Only admins can manage users." onBack={onBack} />);
    expect(screen.getByRole("header", { name: "Users" })).toBeOnTheScreen();
    expect(screen.getByText("Only admins can manage users.")).toBeOnTheScreen();
    await fireEvent.press(screen.getByRole("button", { name: "Back to Bots" }));
    await fireEvent.press(screen.getByText("Back to Bots"));
    expect(onBack).toHaveBeenCalledTimes(2);
  });
});

describe("RouteScreen", () => {
  it.each(["light", "dark"] as const)("puts the screen on the %s canvas, at rest without motion styles", async (scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(scheme);
    await render(
      <RouteScreen>
        <RN.Text>Body</RN.Text>
      </RouteScreen>,
    );
    expect(screen.getByText("Body")).toBeOnTheScreen();
    expect(flat("route-screen").opacity).toBeUndefined();
  });
});

describe("DetailSheet", () => {
  it("has the shared header, and goes back from its pill and the system back", async () => {
    const onClose = jest.fn();
    await render(
      <DetailSheet visible onClose={onClose} backText="‹ Roles" backLabel="Back to roles">
        <RN.Text>Role detail</RN.Text>
      </DetailSheet>,
    );
    expect(screen.getByText("Role detail")).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Back to roles" })).toHaveTextContent("‹ Roles");
    await fireEvent.press(screen.getByRole("button", { name: "Back to roles" }));
    await act(async () => screen.getByTestId("detail-sheet").props.onRequestClose());
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it.each([
    [false, "slide"],
    [true, "none"],
  ] as const)("with reduced motion %s, comes in with %s", async (on, animation) => {
    reduceMotion(on);
    await render(
      <DetailSheet visible onClose={() => {}} backText="‹ Users">
        <RN.Text>Detail</RN.Text>
      </DetailSheet>,
    );
    await act(async () => {});
    expect(screen.getByTestId("detail-sheet").props.animationType).toBe(animation);
  });
});

describe("motion", () => {
  it("takes durations from the tokens, and none with reduced motion", async () => {
    reduceMotion(false);
    const plain = await renderHook(() => useMotion());
    await act(async () => {});
    expect(plain.result.current.duration("base")).toBe(themes.light.motion.base);
    expect(plain.result.current.duration("slow")).toBe(themes.light.motion.slow);

    reduceMotion(true);
    const reduced = await renderHook(() => useMotion());
    await act(async () => {});
    expect(reduced.result.current.reduced).toBe(true);
    expect(reduced.result.current.duration("base")).toBe(0);
    const modal = await renderHook(() => useModalAnimation());
    await act(async () => {});
    expect(modal.result.current).toBe("none");
  });

  it("brings a new pane in over the tokens' base duration, and rests without a transform", async () => {
    reduceMotion(false);
    const start = jest.fn();
    const timing = jest.spyOn(Animated, "timing").mockReturnValue({ start, stop: jest.fn(), reset: jest.fn() } as unknown as RN.Animated.CompositeAnimation);
    const { rerender } = await render(
      <PaneTransition paneKey="list" from="right" testID="pane">
        <RN.Text>List</RN.Text>
      </PaneTransition>,
    );
    await act(async () => {});
    expect(timing).not.toHaveBeenCalled();
    expect(flat("pane").transform).toBeUndefined();
    expect(flat("pane").opacity).toBeUndefined();

    await rerender(
      <PaneTransition paneKey="chat" from="right" testID="pane">
        <RN.Text>Chat</RN.Text>
      </PaneTransition>,
    );
    expect(timing).toHaveBeenCalledTimes(1);
    expect(timing.mock.calls[0][1]).toMatchObject({ toValue: 1, duration: themes.light.motion.base });
    expect(screen.getByText("Chat")).toBeOnTheScreen();
    expect(flat("pane")).toMatchObject({ opacity: 0, transform: [{ translateX: 12 }] });

    await act(async () => start.mock.calls[0][0]({ finished: true }));
    expect(flat("pane").transform).toBeUndefined();
  });

  it("just shows the new pane when the device asks for less motion", async () => {
    reduceMotion(true);
    const timing = jest.spyOn(Animated, "timing");
    const { rerender } = await render(
      <PaneTransition paneKey="list" testID="pane">
        <RN.Text>List</RN.Text>
      </PaneTransition>,
    );
    await act(async () => {});
    await rerender(
      <PaneTransition paneKey="chat" testID="pane">
        <RN.Text>Chat</RN.Text>
      </PaneTransition>,
    );
    expect(timing).not.toHaveBeenCalled();
    expect(screen.getByText("Chat")).toBeOnTheScreen();
    expect(flat("pane").opacity).toBeUndefined();
    expect(flat("pane").transform).toBeUndefined();
  });

  it("keeps still while the device's setting is still on its way", async () => {
    jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockReturnValue(new Promise(() => {}));
    const timing = jest.spyOn(Animated, "timing");
    const motion = await renderHook(() => useMotion());
    expect(motion.result.current.reduced).toBe(true);
    expect(motion.result.current.duration("base")).toBe(0);
    const { rerender } = await render(
      <PaneTransition appear paneKey="list" testID="pane">
        <RN.Text>List</RN.Text>
      </PaneTransition>,
    );
    await rerender(
      <PaneTransition appear paneKey="chat" testID="pane">
        <RN.Text>Chat</RN.Text>
      </PaneTransition>,
    );
    expect(timing).not.toHaveBeenCalled();
    expect(flat("pane").opacity).toBeUndefined();
    await render(
      <DetailSheet visible onClose={() => {}} backText="‹ Users">
        <RN.Text>Detail</RN.Text>
      </DetailSheet>,
    );
    expect(screen.getByTestId("detail-sheet").props.animationType).toBe("none");
  });

  it.each([
    [false, 1],
    [true, 0],
  ] as const)("on web, reads prefers-reduced-motion (%s) at once, so a screen comes in or not from its first frame", async (matches, runs) => {
    jest.replaceProperty(RN.Platform, "OS", "web");
    const matchMedia = jest.fn(() => ({ matches }));
    Object.defineProperty(globalThis, "matchMedia", { value: matchMedia, configurable: true, writable: true });
    jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockReturnValue(new Promise(() => {}));
    const timing = jest.spyOn(Animated, "timing").mockReturnValue({ start: jest.fn(), stop: jest.fn(), reset: jest.fn() } as unknown as RN.Animated.CompositeAnimation);
    try {
      await render(
        <PaneTransition appear testID="pane">
          <RN.Text>Screen</RN.Text>
        </PaneTransition>,
      );
      expect(matchMedia).toHaveBeenCalledWith("(prefers-reduced-motion: reduce)");
      expect(timing).toHaveBeenCalledTimes(runs);
      expect(flat("pane").opacity).toBe(matches ? undefined : 0);
    } finally {
      delete (globalThis as { matchMedia?: unknown }).matchMedia;
    }
  });
});

describe("the root stack", () => {
  it.each(["light", "dark"] as const)("lays every screen on the %s canvas, with a status bar that reads on it", (scheme) => {
    const t = themes[scheme];
    expect(stackOptions(t, false)).toEqual({ headerShown: false, contentStyle: { backgroundColor: t.c.bg }, animation: "default" });
    expect(statusBarStyle(scheme)).toBe(scheme === "dark" ? "light" : "dark");
  });

  it("drops the push animation with reduced motion", () => {
    expect(stackOptions(themes.light, true).animation).toBe("none");
  });
});
