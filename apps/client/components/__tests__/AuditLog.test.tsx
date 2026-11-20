import React from "react";
import { act, fireEvent, render, screen, userEvent, within } from "@testing-library/react-native";
import { AuditLog } from "../AuditLog";
import { ApiError, type SuperBotApi } from "../../src/api";
import { saveCsv } from "../../src/saveCsv";
import type { AuditEvent, AuditPage } from "../../src/types";

jest.mock("../../src/saveCsv", () => ({ saveCsv: jest.fn(async () => {}) }));

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

beforeEach(() => jest.mocked(saveCsv).mockClear());

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

  it("opens an event to show its session, subject, and user agent", async () => {
    const { user } = await open([{ events: [ev(1, { sessionId: "s1", actorSubject: "https://login.example/t1|oid-1", userAgent: "Firefox" })], nextBefore: null }]);
    const row = await screen.findByLabelText("Audit event 1: bot.created");
    expect(screen.queryByText("Session s1")).toBeNull();
    await user.press(row);
    expect(screen.getByText("Session s1")).toBeOnTheScreen();
    expect(screen.getByText("IdP subject https://login.example/t1|oid-1")).toBeOnTheScreen();
    expect(screen.getByText("User agent Firefox")).toBeOnTheScreen();
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
    expect(await screen.findByText("No events match.")).toBeOnTheScreen();
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
    expect(await screen.findByText("Admins only")).toBeOnTheScreen();
    await user.press(screen.getByText("Export CSV"));
    expect(await screen.findAllByText("Admins only")).toHaveLength(2);
    expect(saveCsv).not.toHaveBeenCalled();
  });
});
