import React from "react";
import { act, fireEvent, render, screen, userEvent } from "@testing-library/react-native";
import { CONFIRM_EVERY_MS, PlanView } from "../PlanView";
import PlanScreen from "../../app/plan";
import { ApiError } from "../../src/api";
import { BILLING_OFF } from "../../src/billing";
import type { BillingEmails, BillingView, MyUsage } from "../../src/types";

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

const totals = { input: 1000, output: 200, cacheRead: 300, cacheWrite: 0, total: 1500, runs: 1, unreportedRuns: 0 };
const usage: MyUsage = {
  user: "u1",
  tier: starter,
  period: { key: "2026-11", start: Date.UTC(2026, 10, 1), end: Date.UTC(2026, 11, 1), source: "calendar" },
  tokens: { ...totals, limit: null },
  runs: { used: 12, limit: 300 },
  byBot: [{ ...totals, bot: "b1", name: "Scout" }],
};

function fakeApi(view: BillingView | null, mine: MyUsage | null = null, emails: BillingEmails | null = null) {
  return {
    billingEmails: jest.fn(async (): Promise<BillingEmails | null> => emails),
    billing: jest.fn(async (): Promise<BillingView | null> => view),
    myUsage: jest.fn(async (): Promise<MyUsage | null> => mine),
    checkout: jest.fn(async (tier: string) => ({ url: `https://checkout.stripe.com/c/pay/${tier}` })),
    billingPortal: jest.fn(async () => ({ url: "https://billing.stripe.com/p/session/1" })),
    setUsageEmails: jest.fn(async (on: boolean) => ({ on: true, usage: on })),
  };
}

describe("PlanView (ADR 0042)", () => {
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

  it("warns when storage is nearly full, and says how to free it when full (ADR 0082)", async () => {
    const storage = { used: 950_000, limit: 1_000_000, percent: 95, state: "warning" as const, warnAt: 90, partial: false, measuredAt: 1 };
    const plan = { ...starter, limits: { maxStorageMb: 1 }, usage: { period: "2026-11", runs: 0, bots: 0, storage } };
    const { rerender } = await render(<PlanView api={fakeApi(billing({ plan }))} onBack={jest.fn()} />);
    expect(await screen.findByText("Storage: 950 KB of 1 MB (95%)")).toBeOnTheScreen();
    expect(screen.getByText(/^Storage is 95% full/)).toBeOnTheScreen();
    const full = { ...plan, usage: { ...plan.usage, storage: { ...storage, used: 1_200_000, percent: 120, state: "over" as const } } };
    await rerender(<PlanView api={fakeApi(billing({ plan: full }))} onBack={jest.fn()} />);
    expect(await screen.findByText(/^Storage is full: new messages and tasks are refused/)).toBeOnTheScreen();
    expect(screen.queryByText(/Over this plan's limit for storage/)).toBeNull();
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

  it("says the team pays, and offers no personal upgrade, while a team plan applies (ADR 0093)", async () => {
    await render(<PlanView api={fakeApi(billing({ teamPlan: { id: "t1", name: "Alpha", tier: "pro", periodEnd: 1_797_582_000 } }))} onBack={jest.fn()} />);
    expect(await screen.findByText("Alpha pays for this plan for everyone on it.")).toBeOnTheScreen();
    expect(screen.queryByRole("link", { name: "Upgrade to Pro" })).toBeNull();
    expect(screen.getByText("Your team's owners and admins change its plan on the Team screen.")).toBeOnTheScreen();
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

  it("thanks people back from Stripe, and shows the new plan once Stripe confirms it", async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi(billing());
      await render(<PlanView api={api} onBack={jest.fn()} checkout="success" />);
      expect(await screen.findByText(/Thanks! Your plan changes as soon as Stripe confirms/)).toBeOnTheScreen();
      expect(screen.getByText("Starter plan")).toBeOnTheScreen();
      const paid = billing({
        plan: { ...pro, usage: { period: "2026-11", runs: 12, bots: 3, day: "2026-11-20", routineRuns: 4 } },
        subscription: { status: "active", tier: "pro", periodEnd: null },
        portal: true,
      });
      api.billing.mockResolvedValue(paid);
      await act(async () => {
        jest.advanceTimersByTime(CONFIRM_EVERY_MS);
      });
      expect(await screen.findByText("Pro plan")).toBeOnTheScreen();
      const calls = api.billing.mock.calls.length;
      await act(async () => {
        jest.advanceTimersByTime(CONFIRM_EVERY_MS * 5);
      });
      expect(api.billing.mock.calls.length).toBe(calls);
    } finally {
      jest.useRealTimers();
    }
  });

  it("shows your tokens and runs this period (ADR 0050)", async () => {
    await render(<PlanView api={fakeApi(billing(), usage)} onBack={jest.fn()} />);
    expect(await screen.findByText("Usage this period")).toBeOnTheScreen();
    expect(screen.getByText("This month: 2026-11-01 to 2026-12-01 (UTC)")).toBeOnTheScreen();
    expect(screen.getByText("Model tokens: 1,500 (no limit)")).toBeOnTheScreen();
    expect(screen.getByText("Scout: 1,500 tokens in 1 run")).toBeOnTheScreen();
  });

  it("turns usage emails off and on, when the server sends billing emails (ADR 0091)", async () => {
    const api = fakeApi(billing({ emails: { on: true, usage: true } }));
    await render(<PlanView api={api} onBack={jest.fn()} />);
    const toggle = await screen.findByLabelText("Usage emails");
    expect(toggle.props.value).toBe(true);
    await act(async () => fireEvent(toggle, "valueChange", false));
    expect(api.setUsageEmails).toHaveBeenCalledWith(false);
    expect((await screen.findByLabelText("Usage emails")).props.value).toBe(false);
  });

  it("says why a usage email change didn't save", async () => {
    const api = fakeApi(billing({ emails: { on: true, usage: true } }));
    api.setUsageEmails.mockRejectedValueOnce(new ApiError("Server error", 500));
    await render(<PlanView api={api} onBack={jest.fn()} />);
    const toggle = await screen.findByLabelText("Usage emails");
    await act(async () => fireEvent(toggle, "valueChange", false));
    expect(await screen.findByText("Server error")).toBeOnTheScreen();
    expect(screen.getByLabelText("Usage emails").props.value).toBe(true);
  });

  it("has no email settings when the server sends no billing emails, and read-only people can't change them", async () => {
    const { rerender } = await render(<PlanView api={fakeApi(billing({ emails: { on: false, usage: true } }))} onBack={jest.fn()} />);
    expect(await screen.findByText("Starter plan")).toBeOnTheScreen();
    expect(screen.queryByText("Emails")).toBeNull();
    await rerender(<PlanView api={fakeApi(billing())} onBack={jest.fn()} />);
    expect(await screen.findByText("Starter plan")).toBeOnTheScreen();
    expect(screen.queryByLabelText("Usage emails")).toBeNull();
    await rerender(<PlanView api={fakeApi(billing({ canChange: false, emails: { on: true, usage: true } }))} onBack={jest.fn()} />);
    expect((await screen.findByLabelText("Usage emails")).props.disabled).toBe(true);
  });

  it("offers the usage emails switch on a server that sends them without checkout", async () => {
    const api = fakeApi(null, usage, { on: true, usage: true, canChange: true });
    await render(<PlanView api={api} onBack={jest.fn()} />);
    expect(await screen.findByText(BILLING_OFF)).toBeOnTheScreen();
    const toggle = await screen.findByLabelText("Usage emails");
    await act(async () => fireEvent(toggle, "valueChange", false));
    expect(api.setUsageEmails).toHaveBeenCalledWith(false);
    expect((await screen.findByLabelText("Usage emails")).props.value).toBe(false);
  });

  it("keeps a saved usage email setting when a refresh from before the save lands after it", async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi(billing(), null, { on: true, usage: true, canChange: true });
      await render(<PlanView api={api} onBack={jest.fn()} checkout="success" />);
      expect((await screen.findByLabelText("Usage emails")).props.value).toBe(true);
      let land: (v: BillingEmails) => void = () => {};
      api.billingEmails.mockImplementationOnce(() => new Promise<BillingEmails>((r) => (land = r)));
      await act(async () => {
        jest.advanceTimersByTime(CONFIRM_EVERY_MS);
      });
      await act(async () => fireEvent(screen.getByLabelText("Usage emails"), "valueChange", false));
      expect(screen.getByLabelText("Usage emails").props.value).toBe(false);
      await act(async () => land({ on: true, usage: true, canChange: true }));
      expect(screen.getByLabelText("Usage emails").props.value).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });

  it("takes /api/me/emails over the billing view, read-only included", async () => {
    await render(<PlanView api={fakeApi(billing({ emails: { on: true, usage: true } }), null, { on: true, usage: false, canChange: false })} onBack={jest.fn()} />);
    const toggle = await screen.findByLabelText("Usage emails");
    expect(toggle.props.disabled).toBe(true);
    expect(toggle.props.value).toBe(false);
  });

  it("still shows the plan when usage can't load", async () => {
    const api = fakeApi(billing());
    api.myUsage.mockRejectedValueOnce(new ApiError("Server error", 500));
    await render(<PlanView api={api} onBack={jest.fn()} />);
    expect(await screen.findByText("Starter plan")).toBeOnTheScreen();
    expect(screen.queryByText("Usage this period")).toBeNull();
    expect(screen.queryByText("Server error")).toBeNull();
  });

  it("shows usage on a server without billing", async () => {
    await render(<PlanView api={fakeApi(null, usage)} onBack={jest.fn()} />);
    expect(await screen.findByText(BILLING_OFF)).toBeOnTheScreen();
    expect(screen.getByText("Usage this period")).toBeOnTheScreen();
  });

  it("says plainly that billing is off during testing", async () => {
    await render(<PlanView api={fakeApi(null)} onBack={jest.fn()} />);
    expect(await screen.findByText(BILLING_OFF)).toBeOnTheScreen();
    expect(BILLING_OFF).toMatch(/^Billing is off during testing\. Nothing is charged/);
    expect(screen.queryByText("Plans")).toBeNull();
    expect(screen.queryByText(/Upgrade to/)).toBeNull();
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
