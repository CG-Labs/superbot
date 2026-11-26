import React from "react";
import { act, fireEvent, render, screen, userEvent, within } from "@testing-library/react-native";
import { AuditLog } from "../AuditLog";
import { ApiError, type SuperBotApi } from "../../src/api";
import { saveCsv } from "../../src/saveCsv";
import type { AuditEvent, AuditPage } from "../../src/types";

jest.mock("../../src/saveCsv", () => ({ saveCsv: jest.fn(async () => {}) }));
let mockWidth = 400;
jest.mock("react-native/Libraries/Utilities/useWindowDimensions", () => ({
  __esModule: true,
  default: () => ({ width: mockWidth, height: 800, scale: 1, fontScale: 1 }),
}));

const ev = (id: number, e: Partial<AuditEvent> = {}): AuditEvent => ({
  id,
  at: Date.UTC(2026, 10, 19, 13, 0, id),
  time: `2026-11-19T13:00:${String(id).padStart(2, "0")}.000Z`,
  actorKind: "user",
  actorId: "operator",
  actorName: "Owner",
  actorRole: "admin",
  authMethod: "sso",
  idp: "entra",
  idpProvider: "work",
  action: "bot.created",
  targetType: "bot",
  targetId: "b1",
  outcome: "success",
  ip: "192.0.2.1",
  details: { name: "Scout" },
  ...e,
});

function fakeApi(pages: AuditPage[]) {
  const queue = [...pages];
  return {
    audit: jest.fn(async (_q: string, _before?: number | null) => queue.shift() ?? { events: [], nextBefore: null }),
    auditCsv: jest.fn(async () => "id,time\r\n"),
  };
}

async function open(pages: AuditPage[], botName?: (id: string) => string | undefined) {
  const api = fakeApi(pages);
  const user = userEvent.setup();
  await render(<AuditLog api={api as unknown as SuperBotApi} onBack={jest.fn()} botName={botName} />);
  return { api, user };
}

const lastQuery = (api: ReturnType<typeof fakeApi>) => api.audit.mock.calls.at(-1)?.[0];

beforeEach(() => {
  jest.mocked(saveCsv).mockClear();
  mockWidth = 400;
});

describe("AuditLog", () => {
  it("lists events with who acted, how they signed in, the target, and failures marked", async () => {
    await open([
      {
        events: [
          ev(2, { action: "auth.login_failed", outcome: "failure", actorName: null, actorId: null, actorEmail: "x@example.com", authMethod: "password", actorRole: null, targetType: null, targetId: null, details: {} }),
          ev(1, { actorKind: "bot", actorId: "b9", actorName: null, actorRole: null, authMethod: "bot_token", onBehalfOf: "operator", idp: null, idpProvider: null }),
          ev(0),
        ],
        nextBefore: null,
      },
    ], (id) => (id === "b9" ? "Scout" : undefined));
    const failed = within(await screen.findByLabelText("Audit event 2: auth.login_failed"));
    expect(failed.getByText("failure")).toBeOnTheScreen();
    expect(failed.getByText("x@example.com", { exact: false })).toBeOnTheScreen();
    expect(failed.getByText(" · Password (break-glass)", { exact: false })).toBeOnTheScreen();
    const byBot = within(screen.getByLabelText("Audit event 1: bot.created"));
    expect(byBot.getByText(/^Scout/)).toBeOnTheScreen();
    expect(byBot.getByText(" · Bot token · for Owner", { exact: false })).toBeOnTheScreen();
    const sso = within(screen.getByLabelText("Audit event 0: bot.created"));
    expect(sso.getByText(" · admin · SSO · entra (work)", { exact: false })).toBeOnTheScreen();
    expect(sso.getByText("bot b1 · 192.0.2.1")).toBeOnTheScreen();
    expect(sso.getByText('{"name":"Scout"}')).toBeOnTheScreen();
    expect(sso.queryByText("failure")).toBeNull();
  });

  it("opens an event to show all of it: session, subject, user agent, and details", async () => {
    const { user } = await open([{ events: [ev(1, { sessionId: "s1", actorSubject: "https://login.example/t1|oid-1", userAgent: "Firefox" })], nextBefore: null }]);
    const row = await screen.findByLabelText("Audit event 1: bot.created");
    expect(screen.queryByTestId("audit-event-detail")).toBeNull();
    await user.press(row);
    const detail = within(screen.getByTestId("audit-event-detail"));
    expect(detail.getByText("s1")).toBeOnTheScreen();
    expect(detail.getByText("https://login.example/t1|oid-1")).toBeOnTheScreen();
    expect(detail.getByText("Firefox")).toBeOnTheScreen();
    expect(detail.getByText('{\n  "name": "Scout"\n}')).toBeOnTheScreen();
    expect(detail.queryByText("Decision")).toBeNull();
    await user.press(screen.getByLabelText("Back to the audit log"));
    expect(screen.queryByTestId("audit-event-detail")).toBeNull();
  });

  it("says how an approval was decided, and what it was for", async () => {
    const denied = ev(1, {
      action: "approval.denied",
      targetType: "approval",
      targetId: "a1",
      botId: "b9",
      details: { subject: "git push origin main", tool: "Bash", class: "push", note: "not today", rule: null },
    });
    const { user } = await open([{ events: [denied], nextBefore: null }], (id) => (id === "b9" ? "Scout" : undefined));
    await user.press(await screen.findByLabelText("Audit event 1: approval.denied"));
    const detail = within(screen.getByTestId("audit-event-detail"));
    expect(detail.getByText("Denied")).toBeOnTheScreen();
    expect(detail.getByText("git push origin main")).toBeOnTheScreen();
    expect(detail.getByText("not today")).toBeOnTheScreen();
    expect(detail.getByText("Scout (b9)")).toBeOnTheScreen();
  });

  it("follows a session, a Bot, or a person from an event, starting a fresh filter", async () => {
    const { api, user } = await open([], (id) => (id === "b9" ? "Scout" : undefined));
    api.audit.mockImplementation(async () => ({ events: [ev(1, { sessionId: "s1", botId: "b9" })], nextBefore: null }));
    await user.press(screen.getByText("Filters"));
    await user.press(screen.getByRole("radio", { name: "Failure" }));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("outcome=failure");
    await user.press(await screen.findByLabelText("Audit event 1: bot.created"));
    await user.press(screen.getByText("Everything in this session ›"));
    expect(screen.queryByTestId("audit-event-detail")).toBeNull();
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("session=s1");
    expect(screen.getByLabelText("Session").props.value).toBe("s1");

    await user.press(await screen.findByLabelText("Audit event 1: bot.created"));
    await user.press(screen.getByText("Everything about Scout ›"));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("bot=b9");

    await user.press(await screen.findByLabelText("Audit event 1: bot.created"));
    await user.press(screen.getByText("Everything by Owner ›"));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("actor=user%3Aoperator");
  });

  it("filters by kind of action, Bot, and whom a Bot acted for", async () => {
    const api = fakeApi([{ events: [ev(1)], nextBefore: null }]);
    const user = userEvent.setup();
    const bots = [
      { id: "b2", name: "Zed" },
      { id: "b1", name: "Scout" },
    ];
    await render(<AuditLog api={api as unknown as SuperBotApi} onBack={jest.fn()} bots={bots} />);
    await screen.findByLabelText("Audit event 1: bot.created");
    await user.press(screen.getByText("Filters"));
    expect(screen.getAllByText(/^(Any Bot|Scout|Zed)$/).map((t) => t.props.children)).toEqual(["Any Bot", "Scout", "Zed"]);
    await user.press(screen.getByRole("radio", { name: "Approval decisions" }));
    expect(screen.getByLabelText("Action").props.value).toBe("approval.approved,approval.denied,approval.expired");
    await user.press(screen.getByRole("radio", { name: "Scout" }));
    await user.type(screen.getByLabelText("On behalf of"), "ada@example.com");
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("action=approval.approved%2Capproval.denied%2Capproval.expired&bot=b1&onBehalfOf=ada%40example.com");
    expect(screen.getByRole("radio", { name: "Approval decisions" })).toBeChecked();

    await user.type(screen.getByLabelText("Action"), ",bot.*");
    expect(screen.getByRole("radio", { name: "Approval decisions" })).not.toBeChecked();
    await user.press(screen.getByRole("radio", { name: "Any action" }));
    expect(screen.getByLabelText("Action").props.value).toBe("");
  });

  it("opens with the filters of a link, and shows them", async () => {
    const api = fakeApi([{ events: [], nextBefore: null }]);
    await render(<AuditLog api={api as unknown as SuperBotApi} onBack={jest.fn()} initial={{ bot: "gone" }} botName={() => undefined} />);
    expect(await screen.findByRole("heading", { name: "No events match" })).toBeOnTheScreen();
    expect(screen.getByText("Change or clear the filters to see more.")).toBeOnTheScreen();
    expect(api.audit).toHaveBeenCalledWith("bot=gone", undefined);
    expect(screen.getByText("Hide filters · 1")).toBeOnTheScreen();
    expect(screen.getByRole("radio", { name: "gone" })).toBeChecked();
  });

  it("asks the server again as filters change", async () => {
    const { api, user } = await open([{ events: [ev(1)], nextBefore: null }]);
    await screen.findByLabelText("Audit event 1: bot.created");
    expect(lastQuery(api)).toBe("");
    await user.press(screen.getByText("Filters"));
    await user.type(screen.getByLabelText("Action"), "auth.*");
    await user.press(screen.getByRole("radio", { name: "Bots" }));
    await user.press(screen.getByRole("radio", { name: "SSO" }));
    await user.press(screen.getByRole("radio", { name: "Denied" }));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("action=auth.*&actor=bot&method=sso&outcome=denied");

    await user.type(screen.getByLabelText("Person"), "ada@example.com");
    expect(screen.getByRole("radio", { name: "Bots" })).toBeDisabled();
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("action=auth.*&actor=user%3Aada%40example.com&method=sso&outcome=denied");

    await user.press(screen.getByText("Clear filters"));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("");
  });

  it("filters by whole days, and says what's wrong with a bad date without asking", async () => {
    const { api, user } = await open([{ events: [], nextBefore: null }]);
    expect(await screen.findByRole("heading", { name: "No events match" })).toBeOnTheScreen();
    await user.press(screen.getByText("Filters"));
    await user.type(screen.getByLabelText("From"), "2026-11-01");
    await user.type(screen.getByLabelText("To"), "2026-11-02");
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe(`from=${new Date(2026, 10, 1).getTime()}&to=${new Date(2026, 10, 3).getTime()}`);
    const calls = api.audit.mock.calls.length;
    await fireEvent.changeText(screen.getByLabelText("To"), "2026-10-31");
    expect(screen.getByText("From is after To.")).toBeOnTheScreen();
    await fireEvent.changeText(screen.getByLabelText("To"), "soon");
    expect(screen.getByText('"soon" isn\'t a date. Use YYYY-MM-DD.')).toBeOnTheScreen();
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(api.audit).toHaveBeenCalledTimes(calls);
  });

  it("loads older events with the filter the list came from", async () => {
    const { api, user } = await open([
      { events: [ev(3), ev(2)], nextBefore: 2 },
      { events: [ev(1)], nextBefore: null },
    ]);
    await screen.findByLabelText("Audit event 3: bot.created");
    await user.press(screen.getByText("Load more"));
    expect(await screen.findByLabelText("Audit event 1: bot.created")).toBeOnTheScreen();
    expect(screen.getByLabelText("Audit event 3: bot.created")).toBeOnTheScreen();
    expect(api.audit).toHaveBeenLastCalledWith("", 2);
    expect(screen.queryByText("Load more")).toBeNull();
  });

  it("asks for one older page at a time", async () => {
    const { api, user } = await open([{ events: [ev(3)], nextBefore: 3 }]);
    await screen.findByLabelText("Audit event 3: bot.created");
    let finish: (p: AuditPage) => void = () => {};
    api.audit.mockImplementationOnce(() => new Promise<AuditPage>((r) => (finish = r)));
    await user.press(screen.getByText("Load more"));
    expect(screen.getByText("Loading…")).toBeOnTheScreen();
    await user.press(screen.getByText("Loading…"));
    expect(api.audit).toHaveBeenCalledTimes(2);
    await act(async () => finish({ events: [ev(2)], nextBefore: null }));
    expect(await screen.findByLabelText("Audit event 2: bot.created")).toBeOnTheScreen();
  });

  it("pulls to refresh with the filter on screen", async () => {
    const { api } = await open([
      { events: [ev(1)], nextBefore: null },
      { events: [ev(2), ev(1)], nextBefore: null },
    ]);
    await screen.findByLabelText("Audit event 1: bot.created");
    await fireEvent(screen.getByTestId("audit-list"), "refresh");
    expect(await screen.findByLabelText("Audit event 2: bot.created")).toBeOnTheScreen();
    expect(api.audit).toHaveBeenLastCalledWith("", undefined);
  });

  it("refreshes the filter being loaded, not the one it's replacing", async () => {
    const { api, user } = await open([{ events: [ev(1)], nextBefore: null }]);
    await screen.findByLabelText("Audit event 1: bot.created");
    api.audit.mockImplementationOnce(() => new Promise<AuditPage>(() => {}));
    await user.press(screen.getByText("Filters"));
    await user.press(screen.getByRole("radio", { name: "Failure" }));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("outcome=failure");
    api.audit.mockImplementationOnce(async () => ({ events: [ev(2, { outcome: "failure" })], nextBefore: null }));
    await fireEvent(screen.getByTestId("audit-list"), "refresh");
    expect(lastQuery(api)).toBe("outcome=failure");
    expect(await screen.findByLabelText("Audit event 2: bot.created")).toBeOnTheScreen();
    expect(screen.queryByLabelText("Audit event 1: bot.created")).toBeNull();
    await user.press(screen.getByText("Export CSV"));
    expect(api.auditCsv).toHaveBeenLastCalledWith("outcome=failure");
  });

  it("shows the event beside the list on a wide screen, and keeps it there after following it", async () => {
    mockWidth = 1200;
    const { api, user } = await open([{ events: [ev(1, { sessionId: "s1" })], nextBefore: null }]);
    expect(await screen.findByText("Pick an event to see all of it.")).toBeOnTheScreen();
    expect(screen.queryByText("Filters")).toBeNull();
    await user.press(await screen.findByLabelText("Audit event 1: bot.created"));
    expect(screen.getByTestId("audit-event-detail")).toBeOnTheScreen();
    expect(screen.queryByLabelText("Back to the audit log")).toBeNull();
    await user.press(screen.getByText("Only bot.created ›"));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("action=bot.created");
    expect(screen.getByTestId("audit-event-detail")).toBeOnTheScreen();
  });

  it("exports the shown filter as CSV and saves it under the server's name", async () => {
    const { api, user } = await open([{ events: [ev(1)], nextBefore: null }]);
    await screen.findByLabelText("Audit event 1: bot.created");
    await user.press(screen.getByText("Filters"));
    await user.press(screen.getByRole("radio", { name: "Failure" }));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    await user.press(screen.getByText("Export CSV"));
    expect(api.auditCsv).toHaveBeenCalledWith("outcome=failure");
    expect(saveCsv).toHaveBeenCalledWith(expect.stringMatching(/^superbot-audit-\d{8}-\d{6}\.csv$/), "id,time\r\n");
  });

  it("exports the rows on screen while a new filter is still loading", async () => {
    const { api, user } = await open([{ events: [ev(1)], nextBefore: null }]);
    await screen.findByLabelText("Audit event 1: bot.created");
    let finish: (p: AuditPage) => void = () => {};
    api.audit.mockImplementationOnce(() => new Promise<AuditPage>((r) => (finish = r)));
    await user.press(screen.getByText("Filters"));
    await user.press(screen.getByRole("radio", { name: "Failure" }));
    await act(() => new Promise((r) => setTimeout(r, 350)));
    expect(lastQuery(api)).toBe("outcome=failure");
    await user.press(screen.getByText("Export CSV"));
    expect(api.auditCsv).toHaveBeenLastCalledWith("");
    await act(async () => finish({ events: [ev(2, { outcome: "failure" })], nextBefore: null }));
    await screen.findByLabelText("Audit event 2: bot.created");
    await user.press(screen.getByText("Export CSV"));
    expect(api.auditCsv).toHaveBeenLastCalledWith("outcome=failure");
  });

  it("shows why an export or a load failed", async () => {
    const api = fakeApi([]);
    api.audit.mockRejectedValueOnce(new ApiError("Admins only", 403));
    api.auditCsv.mockRejectedValueOnce(new ApiError("Admins only", 403));
    const user = userEvent.setup();
    await render(<AuditLog api={api as unknown as SuperBotApi} onBack={jest.fn()} />);
    expect(await screen.findByText("Couldn't load the audit log. Admins only")).toBeOnTheScreen();
    await user.press(screen.getByText("Export CSV"));
    expect(await screen.findByText("Admins only")).toBeOnTheScreen();
    expect(screen.getAllByRole("alert")).toHaveLength(2);
    expect(saveCsv).not.toHaveBeenCalled();
  });

  it("shows a skeleton while the log loads, then a retry that loads it", async () => {
    const api = fakeApi([{ events: [ev(1)], nextBefore: null }]);
    let fail: (e: Error) => void = () => {};
    api.audit.mockImplementationOnce(() => new Promise<AuditPage>((_, reject) => (fail = reject)));
    const user = userEvent.setup();
    await render(<AuditLog api={api as unknown as SuperBotApi} onBack={jest.fn()} />);
    expect(await screen.findByRole("progressbar", { name: "Loading the audit log" })).toBeOnTheScreen();
    await act(async () => fail(new TypeError("Failed to fetch")));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load the audit log. Can't reach the server. Check your connection and try again.");
    expect(screen.queryByRole("heading", { name: "No events match" })).toBeNull();
    await user.press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByLabelText("Audit event 1: bot.created")).toBeOnTheScreen();
    expect(api.audit).toHaveBeenLastCalledWith("", undefined);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("keeps the rows when an older page fails, and retries that page", async () => {
    const { api, user } = await open([{ events: [ev(3)], nextBefore: 3 }]);
    await screen.findByLabelText("Audit event 3: bot.created");
    api.audit.mockRejectedValueOnce(new ApiError("HTTP 502", 502));
    await user.press(screen.getByText("Load more"));
    expect(await screen.findByText("Couldn't load older events. The server had a problem. Try again in a moment.")).toBeOnTheScreen();
    expect(screen.getByLabelText("Audit event 3: bot.created")).toBeOnTheScreen();
    api.audit.mockResolvedValueOnce({ events: [ev(2)], nextBefore: null });
    await user.press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByLabelText("Audit event 2: bot.created")).toBeOnTheScreen();
    expect(api.audit).toHaveBeenLastCalledWith("", 3);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says when nothing has been recorded, without filters to change", async () => {
    await open([{ events: [], nextBefore: null }]);
    expect(await screen.findByRole("heading", { name: "No events match" })).toBeOnTheScreen();
    expect(screen.getByText("Nothing has been recorded yet.")).toBeOnTheScreen();
  });

  it("shows a bad filter as an alert", async () => {
    const { user } = await open([{ events: [], nextBefore: null }]);
    await screen.findByRole("heading", { name: "No events match" });
    await user.press(screen.getByRole("button", { name: "Filters" }));
    await fireEvent.changeText(screen.getByLabelText("From"), "later");
    expect(screen.getByRole("alert")).toHaveTextContent('"later" isn\'t a date. Use YYYY-MM-DD.');
  });
});
