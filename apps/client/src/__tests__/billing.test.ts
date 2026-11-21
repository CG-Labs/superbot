import { Linking } from "react-native";
import { ApiError, SuperBotApi } from "../api";
import { billingAvailable, checkoutNotice, limitSummary, openBillingPage, planAvailable, subscriptionLine } from "../billing";

const BASE = "https://bots.example.com";

describe("billing API (ADR 0042)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const answer = (status: number, body: unknown) =>
    (globalThis.fetch = jest.fn(async () => ({ ok: status < 400, status, json: async () => body })) as unknown as typeof fetch);
  const api = () => new SuperBotApi({ baseUrl: BASE, token: "sbs_" + "a".repeat(64) });

  it("reads a server without billing, or from before it, as no billing", async () => {
    for (const status of [404, 403, 405]) {
      answer(status, { error: "Billing is off while SuperBot is in testing: nothing is charged." });
      expect(await api().billing()).toBeNull();
      expect(await billingAvailable(api())).toBe(false);
    }
    answer(500, { error: "boom" });
    await expect(api().billing()).rejects.toBeInstanceOf(ApiError);
    expect(await billingAvailable(api())).toBe(false);
    answer(200, { plan: {}, plans: [], subscription: null, portal: false, canChange: true });
    expect(await billingAvailable(api())).toBe(true);
  });

  it("offers the Plan screen without billing when the server reports usage (ADR 0050)", async () => {
    const fake = (billing: unknown, usage: unknown) => ({
      billing: jest.fn(async () => billing as never),
      myUsage: jest.fn(async () => {
        if (usage instanceof Error) throw usage;
        return usage as never;
      }),
    });
    expect(await planAvailable(fake({ plans: [] }, null))).toBe(true);
    expect(await planAvailable(fake(null, { tokens: {} }))).toBe(true);
    expect(await planAvailable(fake(null, null))).toBe(false);
    expect(await planAvailable(fake(null, new ApiError("boom", 500)))).toBe(false);
  });

  it("asks for a checkout of a plan by name, and for the portal", async () => {
    answer(200, { url: "https://checkout.stripe.com/c/pay/cs_1" });
    expect(await api().checkout("pro")).toEqual({ url: "https://checkout.stripe.com/c/pay/cs_1" });
    expect(globalThis.fetch).toHaveBeenCalledWith(`${BASE}/api/billing/checkout`, expect.objectContaining({ method: "POST", body: JSON.stringify({ tier: "pro" }) }));
    answer(409, { error: "You already pay for a plan. Change it under Manage billing." });
    await expect(api().checkout("pro")).rejects.toThrow("You already pay for a plan");
    answer(200, { url: "https://billing.stripe.com/p/session/1" });
    await api().billingPortal();
    expect(globalThis.fetch).toHaveBeenCalledWith(`${BASE}/api/billing/portal`, expect.objectContaining({ method: "POST" }));
  });
});

describe("billing helpers", () => {
  it("sums up what a plan allows", () => {
    expect(limitSummary({ maxBots: 1, monthlyRuns: 3000, dailyRoutineRuns: 24, machineType: "g6-standard-1" })).toEqual([
      "1 Bot",
      "3,000 runs a month",
      "24 routine runs a day",
      "Machine: g6-standard-1",
    ]);
    expect(limitSummary({ maxBots: 10 })).toEqual(["10 Bots", "Unlimited runs", "Unlimited routine runs"]);
    expect(limitSummary({ maxBots: 3, concurrentRuns: 3 })).toEqual(["3 Bots", "Unlimited runs", "Unlimited routine runs", "3 tasks at once"]);
    expect(limitSummary({ maxBots: 10, monthlyTokens: 5_000_000 })).toEqual(["10 Bots", "Unlimited runs", "5,000,000 model tokens a month", "Unlimited routine runs"]);
    expect(limitSummary({ maxBots: 3, maxStorageMb: 5000 }).at(-1)).toBe("5 GB of storage");
  });

  it("says how the subscription stands", () => {
    expect(subscriptionLine(null)).toBeNull();
    expect(subscriptionLine({ status: "active", tier: "pro", periodEnd: 1_797_582_000 })).toBe("Paid through Stripe · current period ends 18 Dec 2026");
    expect(subscriptionLine({ status: "past_due", tier: "pro", periodEnd: null })).toBe("Payment overdue: Stripe is retrying your card");
    expect(subscriptionLine({ status: "something_new", tier: "pro", periodEnd: null })).toBe("Stripe says: something new");
  });

  it("thanks people back from checkout, and says nothing was charged when they cancel", () => {
    expect(checkoutNotice("success")?.good).toBe(true);
    expect(checkoutNotice("success", true)?.text).toMatch(/team's plan changes for everyone/);
    expect(checkoutNotice("cancelled", true)?.good).toBe(false);
    expect(checkoutNotice(["cancelled"])).toEqual({ text: "Checkout cancelled. Nothing was charged.", good: false });
    expect(checkoutNotice(undefined)).toBeNull();
    expect(checkoutNotice("<script>")).toBeNull();
  });

  it("opens only https pages", async () => {
    const open = jest.spyOn(Linking, "openURL").mockResolvedValue(undefined);
    await openBillingPage("https://checkout.stripe.com/c/pay/cs_1");
    expect(open).toHaveBeenCalledWith("https://checkout.stripe.com/c/pay/cs_1");
    await expect(openBillingPage("javascript:alert(1)")).rejects.toThrow("isn't https");
    await expect(openBillingPage("http://checkout.stripe.com/")).rejects.toThrow("isn't https");
    expect(open).toHaveBeenCalledTimes(1);
    open.mockRestore();
  });
});
