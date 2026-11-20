import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { PlanView } from "../PlanView";
import PlanScreen from "../../app/plan";
import { ApiError } from "../../src/api";
import type { BillingView } from "../../src/types";

const mockCtx: Record<string, unknown> = {};
const mockRedirect = jest.fn((_href: string) => null);
const mockParams: Record<string, string> = {};
jest.mock("expo-router", () => ({
  Redirect: ({ href }: { href: string }) => mockRedirect(href),
  router: { canGoBack: () => false, back: jest.fn(), replace: jest.fn() },
  useLocalSearchParams: () => mockParams,
}));
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

const starter = { name: "starter", label: "Starter", managed: true, limits: { maxBots: 2, monthlyRuns: 300, dailyRoutineRuns: 24 } };
const pro = { name: "pro", label: "Pro", managed: true, limits: { maxBots: 10 } };

function billing(over: Partial<BillingView> = {}): BillingView {
  return {
    plan: { ...starter, usage: { period: "2026-11", runs: 12, bots: 3, day: "2026-11-20", routineRuns: 4 } },
    plans: [
      { ...starter, current: true },
      { ...pro, current: false },
    ],
    subscription: null,
    portal: false,
    canChange: true,
    ...over,
  };
}

function fakeApi(view: BillingView | null) {
  return {
    billing: jest.fn(async () => view),
    checkout: jest.fn(async (tier: string) => ({ url: `https://checkout.stripe.com/c/pay/${tier}` })),
    billingPortal: jest.fn(async () => ({ url: "https://billing.stripe.com/p/session/1" })),
  };
}

describe("PlanView (ADR 0041)", () => {
  it("shows the plan against its limits, and upgrades through Stripe Checkout", async () => {
    const api = fakeApi(billing());
    const open = jest.fn(async () => {});
    const user = userEvent.setup();
    await render(<PlanView api={api} onBack={jest.fn()} open={open} />);
    expect(await screen.findByText("Starter plan")).toBeOnTheScreen();
    expect(screen.getByText("Bots: 3 of 2")).toBeOnTheScreen();
    expect(screen.getByText("Runs in 2026-11: 12 of 300")).toBeOnTheScreen();
    expect(screen.getByText(/Over this plan's limit for Bots/)).toBeOnTheScreen();
    expect(screen.getByText("Your plan")).toBeOnTheScreen();
    expect(screen.queryByText("Manage billing")).toBeNull();
    expect(screen.queryByRole("link", { name: "Upgrade to Starter" })).toBeNull();
    await user.press(screen.getByRole("link", { name: "Upgrade to Pro" }));
    expect(api.checkout).toHaveBeenCalledWith("pro");
    expect(open).toHaveBeenCalledWith("https://checkout.stripe.com/c/pay/pro");
  });

  it("sends subscribers to the billing portal instead of a second checkout", async () => {
    const api = fakeApi(billing({ subscription: { status: "active", tier: "starter", periodEnd: 1_797_582_000 }, portal: true }));
    const open = jest.fn(async () => {});
    const user = userEvent.setup();
    await render(<PlanView api={api} onBack={jest.fn()} open={open} />);
    expect(await screen.findByText("Paid through Stripe · current period ends 18 Dec 2026")).toBeOnTheScreen();
    expect(screen.queryByRole("link", { name: "Upgrade to Pro" })).toBeNull();
    expect(screen.getByText("To change or cancel your plan, use Manage billing.")).toBeOnTheScreen();
    await user.press(screen.getByText("Manage billing"));
    expect(api.billingPortal).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledWith("https://billing.stripe.com/p/session/1");
  });

  it("shows read-only people their plan without buttons to change it", async () => {
    await render(<PlanView api={fakeApi(billing({ canChange: false, portal: true }))} onBack={jest.fn()} />);
    expect(await screen.findByText("Starter plan")).toBeOnTheScreen();
    expect(screen.queryByRole("link", { name: "Upgrade to Pro" })).toBeNull();
    expect(screen.queryByText("Manage billing")).toBeNull();
    expect(screen.getByText("To change your plan, ask an admin.")).toBeOnTheScreen();
  });

  it("says what went wrong when Stripe can't open the page", async () => {
    const api = fakeApi(billing());
    api.checkout.mockRejectedValueOnce(new ApiError("Stripe couldn't open the checkout just now.", 502));
    const open = jest.fn(async () => {});
    const user = userEvent.setup();
    await render(<PlanView api={api} onBack={jest.fn()} open={open} />);
    await user.press(await screen.findByRole("link", { name: "Upgrade to Pro" }));
    expect(await screen.findByText("Stripe couldn't open the checkout just now.")).toBeOnTheScreen();
    expect(open).not.toHaveBeenCalled();
  });

  it("thanks people back from Stripe", async () => {
    await render(<PlanView api={fakeApi(billing())} onBack={jest.fn()} checkout="success" />);
    expect(await screen.findByText(/Thanks! Your plan changes as soon as Stripe confirms/)).toBeOnTheScreen();
  });

  it("says so on a server without billing", async () => {
    await render(<PlanView api={fakeApi(null)} onBack={jest.fn()} />);
    expect(await screen.findByText("Billing isn't set up on this server.")).toBeOnTheScreen();
    expect(screen.queryByText("Plans")).toBeNull();
  });
});

describe("plan route", () => {
  beforeEach(() => mockRedirect.mockClear());

  it("waits for the saved session when Stripe sends people back, then shows the plan", async () => {
    Object.assign(mockParams, { checkout: "cancelled" });
    Object.assign(mockCtx, { ready: false, api: null });
    await render(<PlanScreen />);
    expect(mockRedirect).not.toHaveBeenCalled();
    Object.assign(mockCtx, { ready: true, api: fakeApi(billing()) });
    await render(<PlanScreen />);
    expect(await screen.findByText("Checkout cancelled. Nothing was charged.")).toBeOnTheScreen();
    expect(screen.getByText("Starter plan")).toBeOnTheScreen();
  });

  it("sends people who aren't signed in to sign in", async () => {
    Object.assign(mockCtx, { ready: true, api: null });
    await render(<PlanScreen />);
    expect(mockRedirect).toHaveBeenCalledWith("/");
  });
});
