import React from "react";
import { AccessibilityInfo, Animated, Platform, Text } from "react-native";
import { act, fireEvent, render, renderHook, screen } from "@testing-library/react-native";
import { ConnectionBanner, RECONNECT_GRACE_MS, useConnectionStatus } from "../ConnectionBanner";
import { EmptyState } from "../EmptyState";
import { ErrorState, InlineError } from "../ErrorState";
import { PillButton } from "../PillButton";
import { AppSkeleton, ChatSkeleton, ListSkeleton, ThinkingDots } from "../Skeleton";
import { TOAST_LONG_MS, TOAST_MS, ToastProvider, useToast, type ToastApi } from "../Toast";
import { ApiError } from "../../src/api";
import { showError } from "../../src/dialogs";

jest.mock("../../src/dialogs", () => ({ showError: jest.fn() }));

function reduceMotion(on: boolean) {
  jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled").mockResolvedValue(on);
}

afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

describe("EmptyState", () => {
  it("names the state as a heading, explains it and offers the next step", async () => {
    const onPress = jest.fn();
    await render(<EmptyState glyph="+" title="No Bots yet" message="Make one to start." action={{ label: "New Bot", onPress }} />);
    expect(screen.getByRole("heading", { name: "No Bots yet" })).toBeOnTheScreen();
    expect(screen.getByText("Make one to start.")).toBeOnTheScreen();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "New Bot" })));
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it("keeps its glyph away from screen readers and shows no buttons without actions", async () => {
    await render(<EmptyState glyph="✓" title="You're all caught up" compact />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText("✓", { includeHiddenElements: true })).not.toBeVisible();
  });

  it("shows a secondary action beside the primary one", async () => {
    const onSecondary = jest.fn();
    await render(
      <EmptyState title="No matches" action={{ label: "Clear search", onPress: jest.fn() }} secondaryAction={{ label: "New Bot", onPress: onSecondary }} />,
    );
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "New Bot" })));
    expect(onSecondary).toHaveBeenCalledTimes(1);
  });
});

describe("ErrorState", () => {
  it("announces the error with a title, the reason and a retry", async () => {
    const onRetry = jest.fn();
    await render(<ErrorState title="Couldn't load this chat" message="The server had a problem." onRetry={onRetry} />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/Couldn't load this chat.*The server had a problem\./);
    expect(alert).toHaveProp("aria-live", "assertive");
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Try again" })));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("stays busy while a retry runs and takes no second press", async () => {
    let finish!: () => void;
    const onRetry = jest.fn(() => new Promise<void>((r) => (finish = r)));
    await render(<ErrorState message="Can't reach the server." onRetry={onRetry} />);
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Try again" })));
    const busy = screen.getByRole("button", { name: "Trying…" });
    expect(busy).toBeDisabled();
    await act(async () => fireEvent.press(busy));
    expect(onRetry).toHaveBeenCalledTimes(1);
    await act(async () => finish());
    expect(screen.getByRole("button", { name: "Try again" })).toBeEnabled();
  });

  it("has no retry button when nothing can be retried", async () => {
    await render(<ErrorState message="Screens are off on this server." />);
    expect(screen.getByRole("alert")).toHaveTextContent(/Something went wrong/);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("fits a one-line error with a retry link into a list", async () => {
    const onRetry = jest.fn();
    await render(<InlineError message="Couldn't load routines." onRetry={onRetry} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/Couldn't load routines\./);
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Try again" })));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

describe("PillButton", () => {
  it("shows its busy label and is disabled while busy", async () => {
    const onPress = jest.fn();
    await render(<PillButton label="Save" busy busyLabel="Saving…" onPress={onPress} />);
    const btn = screen.getByRole("button", { name: "Saving…" });
    expect(btn).toBeDisabled();
    expect(btn).toBeBusy();
  });
});

describe("skeletons", () => {
  it.each([
    ["Loading messages", <ChatSkeleton key="c" />],
    ["Loading routines", <ListSkeleton key="l" label="Loading routines" />],
    ["Loading SuperBot", <AppSkeleton key="a" />],
  ])("are one busy element named %s for screen readers", async (name, el) => {
    await render(el);
    const group = screen.getByRole("progressbar", { name });
    expect(group).toBeBusy();
  });

  it.each([
    ["skeletons", <ChatSkeleton key="c" />],
    ["thinking dots", <ThinkingDots key="d" />],
  ])("%s move, and hold still when the device asks for reduced motion", async (_, el) => {
    let running = 0;
    jest.spyOn(Animated, "loop").mockImplementation(
      () => ({ start: () => void running++, stop: () => void running--, reset: () => {} }) as Animated.CompositeAnimation,
    );
    reduceMotion(false);
    const view = await render(el);
    await act(async () => {});
    expect(running).toBeGreaterThan(0);
    await view.unmount();
    expect(running).toBe(0);

    reduceMotion(true);
    await render(el);
    await act(async () => {});
    expect(running).toBe(0);
  });

  it("keep the thinking dots away from screen readers", async () => {
    await render(<ThinkingDots />);
    expect(screen.getByTestId("thinking-dots", { includeHiddenElements: true })).not.toBeVisible();
  });
});

describe("ConnectionBanner", () => {
  it("shows nothing while online", async () => {
    await render(<ConnectionBanner status="online" />);
    expect(screen.queryByTestId("connection-banner")).toBeNull();
  });

  it.each([
    ["reconnecting", /Reconnecting/],
    ["offline", /You're offline/],
  ] as const)("says when it's %s, politely", async (status, text) => {
    await render(<ConnectionBanner status={status} />);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent(text);
    expect(banner).toHaveProp("aria-live", "polite");
  });

  it("waits out a short drop before saying it's reconnecting", async () => {
    jest.useFakeTimers();
    const { result, rerender } = await renderHook(({ connected }: { connected: boolean }) => useConnectionStatus(connected), { initialProps: { connected: true } });
    expect(result.current).toBe("online");

    await rerender({ connected: false });
    expect(result.current).toBe("online");
    await act(async () => jest.advanceTimersByTime(RECONNECT_GRACE_MS));
    expect(result.current).toBe("reconnecting");

    await rerender({ connected: true });
    expect(result.current).toBe("online");
  });
});

describe("toasts", () => {
  let api!: ToastApi;
  function Grab() {
    api = useToast();
    return <Text>app</Text>;
  }

  it("show a message politely and hide it after a while", async () => {
    jest.useFakeTimers();
    await render(
      <ToastProvider>
        <Grab />
      </ToastProvider>,
    );
    await act(async () => api.show({ message: "Back online", tone: "success" }));
    const toast = screen.getByRole("status");
    expect(toast).toHaveTextContent(/Back online/);
    expect(toast).toHaveProp("aria-live", "polite");
    await act(async () => jest.advanceTimersByTime(TOAST_MS));
    expect(screen.queryByTestId("toast")).toBeNull();
  });

  it("say what failed and why, assertively, and stay longer", async () => {
    jest.useFakeTimers();
    const retry = jest.fn();
    await render(
      <ToastProvider>
        <Grab />
      </ToastProvider>,
    );
    await act(async () => api.error(new TypeError("Failed to fetch"), "Couldn't send your message", { label: "Retry", onPress: retry }));
    const toast = screen.getByRole("alert");
    expect(toast).toHaveTextContent(/Couldn't send your message\. Can't reach the server\. Check your connection and try again\./);
    expect(toast).toHaveProp("aria-live", "assertive");

    await act(async () => jest.advanceTimersByTime(TOAST_MS));
    expect(screen.getByTestId("toast")).toBeOnTheScreen();
    await act(async () => jest.advanceTimersByTime(TOAST_LONG_MS - TOAST_MS));
    expect(screen.queryByTestId("toast")).toBeNull();
    expect(retry).not.toHaveBeenCalled();
  });

  it("run their action once and close", async () => {
    const undo = jest.fn();
    await render(
      <ToastProvider>
        <Grab />
      </ToastProvider>,
    );
    await act(async () => api.show({ message: "Bot hidden", action: { label: "Undo", onPress: undo } }));
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Undo" })));
    expect(undo).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId("toast")).toBeNull();
  });

  it("can be dismissed, and a newer toast replaces an older one", async () => {
    await render(
      <ToastProvider>
        <Grab />
      </ToastProvider>,
    );
    await act(async () => api.show({ message: "First" }));
    await act(async () => api.error(new ApiError("HTTP 503", 503), "Couldn't stop it"));
    expect(screen.queryByText("First")).toBeNull();
    expect(screen.getByText("Couldn't stop it. The server had a problem. Try again in a moment.")).toBeOnTheScreen();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Dismiss" })));
    expect(screen.queryByTestId("toast")).toBeNull();
  });

  it("can be hidden by id, without hiding a newer one", async () => {
    await render(
      <ToastProvider>
        <Grab />
      </ToastProvider>,
    );
    let first = 0;
    await act(async () => {
      first = api.show({ message: "First" });
    });
    let second = 0;
    await act(async () => {
      second = api.show({ message: "Second" });
    });
    await act(async () => api.dismiss(first));
    expect(screen.getByText("Second")).toBeOnTheScreen();
    await act(async () => api.dismiss(second));
    expect(screen.queryByTestId("toast")).toBeNull();
  });

  it("are read out on iOS, which has no live regions", async () => {
    const announce = jest.spyOn(AccessibilityInfo, "announceForAccessibility").mockImplementation(() => {});
    const os = Platform.OS;
    Object.defineProperty(Platform, "OS", { value: "ios", configurable: true });
    try {
      await render(
        <ToastProvider>
          <Grab />
        </ToastProvider>,
      );
      await act(async () => api.show({ message: "Copied" }));
      expect(announce).toHaveBeenCalledWith("Copied");
    } finally {
      Object.defineProperty(Platform, "OS", { value: os, configurable: true });
    }
  });

  it("fall back to a dialog for errors outside a provider", async () => {
    await render(<Grab />);
    api.error(new ApiError("HTTP 404", 404), "Couldn't open it");
    expect(showError).toHaveBeenCalledWith(new Error("Couldn't open it. That isn't there anymore."));
    (showError as jest.Mock).mockClear();
    api.show({ message: "Saved" });
    expect(showError).not.toHaveBeenCalled();
  });
});
