import { Linking, Platform } from "react-native";
import type { SuperBotApi } from "./api";
import type { BillingView, TierView } from "./types";

/** Whether this server sells plans, so the app shows its Plan screen (ADR 0042). */
export async function billingAvailable(api: Pick<SuperBotApi, "billing">): Promise<boolean> {
  try {
    return (await api.billing()) !== null;
  } catch {
    return false;
  }
}

/** Whether to offer the Plan screen: the server sells plans, or reports your usage (ADR 0048). */
export async function planAvailable(api: Pick<SuperBotApi, "billing" | "myUsage">): Promise<boolean> {
  if (await billingAvailable(api)) return true;
  try {
    return (await api.myUsage()) !== null;
  } catch {
    return false;
  }
}

/** What a plan allows, one short line each, for choosing between plans. */
export function limitSummary(limits: TierView["limits"]): string[] {
  const n = (v: number | null | undefined, one: string, many: string, none: string) =>
    v == null ? none : `${v.toLocaleString("en-GB")} ${v === 1 ? one : many}`;
  const lines = [
    n(limits.maxBots, "Bot", "Bots", "Unlimited Bots"),
    n(limits.monthlyRuns, "run a month", "runs a month", "Unlimited runs"),
    n(limits.dailyRoutineRuns, "routine run a day", "routine runs a day", "Unlimited routine runs"),
  ];
  if (limits.monthlyTokens != null) lines.splice(2, 0, n(limits.monthlyTokens, "model token a month", "model tokens a month", ""));
  if (limits.machineType) lines.push(`Machine: ${limits.machineType}`);
  return lines;
}

const STATUS: Record<string, string> = {
  active: "Paid through Stripe",
  trialing: "On a free trial",
  past_due: "Payment overdue: Stripe is retrying your card",
};

/** How the subscription paying for the plan stands, or null when nothing pays for it. */
export function subscriptionLine(sub: BillingView["subscription"]): string | null {
  if (!sub) return null;
  const status = STATUS[sub.status] ?? `Stripe says: ${sub.status.replace(/_/g, " ")}`;
  if (sub.periodEnd == null) return status;
  const date = new Date(sub.periodEnd * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  return `${status} · current period ends ${date}`;
}

/** What to say when Stripe sends someone back (`?checkout=` on the return link). */
export function checkoutNotice(param: string | string[] | undefined): { text: string; good: boolean } | null {
  const v = Array.isArray(param) ? param[0] : param;
  if (v === "success") return { text: "Thanks! Your plan changes as soon as Stripe confirms the payment, usually within a minute.", good: true };
  if (v === "cancelled") return { text: "Checkout cancelled. Nothing was charged.", good: false };
  return null;
}

/**
 * Opens a Stripe page botd made. Only https links: the page is Stripe's. On web this tab
 * goes there, since Stripe sends people back to the app; on phones, the system browser.
 */
export async function openBillingPage(url: string): Promise<void> {
  if (!/^https:\/\//.test(url)) throw new Error("The server sent a link that isn't https.");
  if (Platform.OS === "web" && typeof window !== "undefined") {
    window.location.assign(url);
    return;
  }
  await Linking.openURL(url);
}
