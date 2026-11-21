import React from "react";
import { render, screen, userEvent, within } from "@testing-library/react-native";
import { NotificationsCard, type NotificationsApi } from "../NotificationsCard";
import type { BotNotificationsPatch, BotNotificationsView, BotNotifySettings, NotificationsPatch, NotificationsView } from "../../src/types";
jest.setTimeout(20_000);

/** A fake botd for ADR 0061: global settings, a webhook URL kept secret, and per-Bot settings where null inherits. */
function fakeApi(opts: { smtp?: boolean } = {}) {
  let url: string | null = null;
  const own = new Map<string, string>();
  const overrides = new Map<string, BotNotifySettings>();
  const view: NotificationsView = {
    settings: { email: { enabled: false, to: [], deciders: true }, webhook: { enabled: false, format: "slack" }, delaySeconds: 30, throttleSeconds: 120, detail: "summary" },
    email: { configured: opts.smtp ?? true, server: opts.smtp === false ? null : "smtp.example.com:587 (STARTTLS)", passwordSet: true },
    webhook: { set: false, host: null, store: null, writable: true },
    signing: false,
    links: { app: "https://bots.example.com/app/", console: "https://bots.example.com/console/" },
    bots: [],
  };
  const botView = (id: string): BotNotificationsView => ({
    botId: id,
    override: overrides.get(id) ?? {},
    webhook: { set: own.has(id), host: own.has(id) ? new URL(own.get(id)!).host : null, store: own.has(id) ? "sealed" : null, writable: true },
    global: { email: view.settings.email.enabled, webhook: view.settings.webhook.enabled && !!url, format: view.settings.webhook.format },
    reaches: { email: 0, deciders: [{ id: "u1", name: "Ada", hasEmail: true }, { id: "u2", name: "Bo", hasEmail: false }], webhook: own.has(id) ? "own" : null },
  });
  const copy = () => JSON.parse(JSON.stringify(view)) as NotificationsView;
  return {
    notifications: jest.fn(async () => copy()),
    patchNotifications: jest.fn(async (p: NotificationsPatch) => {
      if (p.email?.enabled && !view.email.configured) throw new Error("Email needs an SMTP server");
      Object.assign(view.settings.email, p.email ?? {});
      const { url: u, ...hook } = p.webhook ?? {};
      if (u !== undefined) {
        url = u;
        view.webhook = { ...view.webhook, set: !!u, host: u ? new URL(u).host : null };
      }
      Object.assign(view.settings.webhook, hook);
      for (const k of ["delaySeconds", "throttleSeconds", "detail"] as const) if (p[k] !== undefined) Object.assign(view.settings, { [k]: p[k] });
      return copy();
    }),
    testNotifications: jest.fn(async () => ({ ok: false, results: [{ channel: "email", ok: true }, { channel: "webhook", ok: false, error: "the webhook answered HTTP 404" }] })),
    botNotifications: jest.fn(async (id: string) => botView(id)),
    patchBotNotifications: jest.fn(async (id: string, p: BotNotificationsPatch) => {
      const o: BotNotifySettings = { ...overrides.get(id) };
      for (const k of ["email", "webhook", "format"] as const) {
        if (p[k] === null) delete o[k];
        else if (p[k] !== undefined) Object.assign(o, { [k]: p[k] });
      }
      overrides.set(id, o);
      if (p.webhookUrl === null) own.delete(id);
      else if (p.webhookUrl) own.set(id, p.webhookUrl);
      return botView(id);
    }),
  } satisfies NotificationsApi;
}

beforeAll(async () => {
  const { unmount } = await render(<NotificationsCard api={fakeApi()} />);
  await screen.findByLabelText("Email addresses");
  await unmount();
}, 60_000);
beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.useRealTimers());

describe("NotificationsCard (ADR 0061)", () => {
  it("turns email on for a list of addresses and saves a webhook URL without showing it again", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<NotificationsCard api={api} />);
    expect(await screen.findByText("Sent through smtp.example.com:587 (STARTTLS).")).toBeOnTheScreen();
    const email = screen.getByLabelText("Email");
    await user.press(within(email).getByRole("radio", { name: "On" }));
    expect(api.patchNotifications).toHaveBeenLastCalledWith({ email: { enabled: true } });
    expect(await screen.findByText("Email on.")).toBeOnTheScreen();

    const to = screen.getByLabelText("Email addresses");
    await user.type(to, "ops@example.com nope");
    expect(screen.getByText('"nope" isn\'t an email address.')).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Save email addresses" })).toBeDisabled();
    await user.clear(to);
    await user.type(to, "ops@example.com, oncall@example.com");
    await user.press(screen.getByRole("button", { name: "Save email addresses" }));
    expect(api.patchNotifications).toHaveBeenLastCalledWith({ email: { to: ["ops@example.com", "oncall@example.com"] } });

    const hook = screen.getByLabelText("Webhook");
    expect(within(hook).getByRole("radio", { name: "On" })).toBeDisabled();
    await user.type(screen.getByLabelText("Webhook URL"), "http://hooks.example.com/x");
    expect(screen.getByText("Use an https URL.")).toBeOnTheScreen();
    await user.clear(screen.getByLabelText("Webhook URL"));
    await user.type(screen.getByLabelText("Webhook URL"), "https://hooks.example.com/services/T0/B0/secret");
    await user.press(screen.getByRole("button", { name: "Save webhook URL" }));
    expect(api.patchNotifications).toHaveBeenLastCalledWith({ webhook: { url: "https://hooks.example.com/services/T0/B0/secret" } });
    expect(await screen.findByText(/URL set \(hooks.example.com\)/)).toBeOnTheScreen();
    expect(screen.queryByDisplayValue(/secret/)).toBeNull();
    await user.press(within(screen.getByLabelText("Webhook")).getByRole("radio", { name: "On" }));
    expect(api.patchNotifications).toHaveBeenLastCalledWith({ webhook: { enabled: true } });
  });

  it("checks the timing and says what a test did", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<NotificationsCard api={api} />);
    const wait = await screen.findByLabelText("Seconds to wait");
    await user.clear(wait);
    await user.type(wait, "601");
    expect(screen.getByText("Use whole seconds from 0 to 600.")).toBeOnTheScreen();
    await user.clear(wait);
    await user.type(wait, "0");
    await user.press(screen.getByRole("button", { name: "Save timing" }));
    expect(api.patchNotifications).toHaveBeenLastCalledWith({ delaySeconds: 0, throttleSeconds: 120 });
    expect(await screen.findByText(/Wait right away first/)).toBeOnTheScreen();

    await user.press(screen.getByRole("button", { name: "Send a test notification" }));
    expect(api.testNotifications).toHaveBeenCalledWith(undefined);
    expect(await screen.findByText("Webhook failed: the webhook answered HTTP 404")).toBeOnTheScreen();
  });

  it("says when the server has no SMTP settings, and keeps email off", async () => {
    await render(<NotificationsCard api={fakeApi({ smtp: false })} />);
    expect(await screen.findByText(/Not set up: set SMTP_HOST and SMTP_FROM/)).toBeOnTheScreen();
    expect(within(screen.getByLabelText("Email")).getByRole("radio", { name: "On" })).toBeDisabled();
  });

  it("sets a Bot's own webhook and puts its email back to the default", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<NotificationsCard api={api} bot={{ id: "b1", name: "Scout" }} />);
    expect(await screen.findByText("Its approvals notify nobody: they wait in the app.")).toBeOnTheScreen();
    expect(screen.getByText("No email address for Bo.")).toBeOnTheScreen();

    const email = screen.getByLabelText("Email for this Bot");
    await user.press(within(email).getByRole("radio", { name: "Off" }));
    expect(api.patchBotNotifications).toHaveBeenLastCalledWith("b1", { email: false });
    await user.press(within(screen.getByLabelText("Email for this Bot")).getByRole("radio", { name: "Default (Off)" }));
    expect(api.patchBotNotifications).toHaveBeenLastCalledWith("b1", { email: null });

    await user.type(screen.getByLabelText("Webhook URL for this Bot"), "https://hooks.example.com/scout");
    await user.press(screen.getByRole("button", { name: "Save webhook URL" }));
    expect(api.patchBotNotifications).toHaveBeenLastCalledWith("b1", { webhookUrl: "https://hooks.example.com/scout" });
    expect(await screen.findByText("Its next approval goes to the Bot's own webhook.")).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Remove webhook URL" }));
    expect(api.patchBotNotifications).toHaveBeenLastCalledWith("b1", { webhookUrl: null });

    await user.press(screen.getByRole("button", { name: "Send a test notification" }));
    expect(api.testNotifications).toHaveBeenCalledWith("b1");
  });
});
