import { act, renderHook, waitFor } from "@testing-library/react-native";
import { clearCredentials, loadSavedCredentials, saveCredentials } from "../auth";
import { connectSse } from "../sse";
import { SuperBotProvider, useSuperBot } from "../SuperBotContext";
import type { Message, Routine, SseEvent } from "../types";

jest.mock("../auth", () => ({
  ...jest.requireActual("../auth"),
  loadSavedCredentials: jest.fn(async () => ({ baseUrl: "https://bots.example.com", password: "hunter2" })),
  saveCredentials: jest.fn(),
  clearCredentials: jest.fn(),
}));
jest.mock("../sse", () => ({ connectSse: jest.fn(() => ({ close: jest.fn() })) }));

const BASE = "https://bots.example.com";
const bot = (id: string, primary = false, unread = false, handoffId: number | null = null) => ({
  id,
  name: id === "b1" ? "Ada" : "Bob",
  color: "#f5f5f5",
  shape: "waddle",
  harness: "claude",
  primary,
  hidden: false,
  unread,
  handoff: handoffId,
  working: false,
});
const handoff: Message = {
  id: 12,
  botId: "b2",
  role: "bot",
  text: "",
  question: { title: "Log in to the bank", options: ["Done", "I can't right now"], handoff: true },
  at: 2,
};
const history: Message[] = [{ id: 11, botId: "b2", role: "bot", text: "Starting", at: 1 }, handoff];
const routine: Routine = { id: "r1", bot_id: "b2", name: "Digest", cron: "0 9 * * *", instruction: "Sum up", enabled: true };

type Call = { url: string; method: string; body?: unknown; headers: Record<string, string> };
let calls: Call[] = [];
let failAnswer = false;
let bobUnread = false;
let bobHandoff: number | null = null;
/** When set, Bob's history request waits until the test calls it. */
let releaseHistory: (() => void) | null = null;
let holdHistory = false;
/** The server's /api/auth/login: absent (an old server), or the token it hands out. */
let loginToken: string | null = null;
let permissions: string[] | undefined;
const TOKEN = "sbs_" + "a".repeat(64);

function respond(status: number, body: unknown) {
  return Promise.resolve({ ok: status < 400, status, json: async () => body });
}

beforeEach(() => {
  calls = [];
  failAnswer = false;
  bobUnread = false;
  bobHandoff = null;
  holdHistory = false;
  releaseHistory = null;
  loginToken = null;
  permissions = undefined;
  (connectSse as jest.Mock).mockClear();
  (saveCredentials as jest.Mock).mockClear();
  (clearCredentials as jest.Mock).mockClear();
  (loadSavedCredentials as jest.Mock).mockImplementation(async () => ({ baseUrl: BASE, password: "hunter2" }));
  globalThis.fetch = jest.fn((url: string, init: RequestInit = {}) => {
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, method, body, headers: (init.headers ?? {}) as Record<string, string> });
    const path = url.slice(BASE.length);
    const auth = ((init.headers ?? {}) as Record<string, string>).Authorization ?? "";
    if (path === "/api/auth/login" && method === "POST") {
      if (!loginToken) return respond(405, {});
      const ok = body.password === "hunter2" || body.code === "sbc_good";
      return ok ? respond(200, { token: loginToken, user: { id: "u1" } }) : respond(401, { error: "Wrong password." });
    }
    if (path === "/api/auth/logout") return respond(200, { ok: true });
    if (loginToken && auth !== `Bearer ${loginToken}`) return respond(401, { error: "Login required" });
    if (path === "/api/state") {
      return respond(200, { me: { name: "Me", permissions }, harnesses: ["claude"], defaultHarness: "claude", bots: [bot("b1", true), bot("b2", false, bobUnread, bobHandoff)] });
    }
    if (path === "/api/bots/b2/messages" && method === "GET") {
      if (!holdHistory) return respond(200, history);
      return new Promise((resolve) => {
        releaseHistory = () => resolve(respond(200, history));
      });
    }
    if (path === "/api/bots/b2/messages" && method === "POST") {
      return failAnswer ? respond(500, { error: "boom" }) : respond(202, { id: 13, botId: "b2", role: "user", text: body.text, at: 3 });
    }
    if (path === "/api/bots/b2/screen") return respond(200, { url: "/screen/6901/?token=voxl" });
    if (path === "/api/bots/b2/routines" && method === "POST") return respond(201, { ...routine, ...body });
    if (path === "/api/routines/r1" && method === "PATCH") return respond(200, { ...routine, ...body });
    if (path === "/api/routines/r1" && method === "DELETE") return respond(200, { ok: true });
    if (path.endsWith("/read")) return respond(200, { ok: true });
    return respond(404, { error: `unexpected ${method} ${path}` });
  }) as unknown as typeof fetch;
});

async function connected() {
  const hook = await renderHook(() => useSuperBot(), { wrapper: SuperBotProvider });
  await waitFor(() => expect(hook.result.current.api).not.toBeNull());
  const onEvent = (connectSse as jest.Mock).mock.calls[0][2] as (e: SseEvent) => void;
  return { ...hook, emit: (e: SseEvent) => act(() => onEvent(e)) };
}

describe("SuperBotProvider", () => {
  it("tracks a live handoff for a Bot whose chat isn't loaded, then loads its full history", async () => {
    const { result, emit } = await connected();

    await emit({ type: "message", message: handoff });
    expect(result.current.handoffs.b2?.id).toBe(12);
    expect(result.current.messages.b2).toBeUndefined();

    await act(() => result.current.loadMessages("b2"));
    expect(result.current.messages.b2.map((m) => m.id)).toEqual([11, 12]);
  });

  it("finds open handoffs of unread Bots on connect without marking them read", async () => {
    bobUnread = true;
    const { result } = await connected();

    await waitFor(() => expect(result.current.handoffs.b2?.id).toBe(12));
    expect(result.current.messages.b2).toHaveLength(2);
    expect(calls.some((c) => c.url.endsWith("/api/bots/b2/read"))).toBe(false);
    expect(calls.some((c) => c.url.endsWith("/api/bots/b1/messages"))).toBe(false);

    await act(() => result.current.loadMessages("b2"));
    expect(calls.filter((c) => c.url.endsWith("/api/bots/b2/messages") && c.method === "GET")).toHaveLength(1);
    expect(calls.some((c) => c.url.endsWith("/api/bots/b2/read"))).toBe(true);
  });

  it("finds a handoff the user read but never answered", async () => {
    bobHandoff = 12;
    const { result } = await connected();
    await waitFor(() => expect(result.current.handoffs.b2?.id).toBe(12));
    expect(calls.some((c) => c.url.endsWith("/api/bots/b2/read"))).toBe(false);
  });

  it("keeps live messages that arrive while a history is loading", async () => {
    bobUnread = true;
    holdHistory = true;
    const { result, emit } = await connected();
    await waitFor(() => expect(releaseHistory).not.toBeNull());

    const reply: Message = { id: 13, botId: "b2", role: "user", text: "Done already", at: 3 };
    await emit({ type: "message", message: reply });
    await act(async () => releaseHistory?.());

    await waitFor(() => expect(result.current.messages.b2?.map((m) => m.id)).toEqual([11, 12, 13]));
    expect(result.current.handoffs.b2).toBeUndefined();
  });

  it("answers a handoff on its own Bot and clears it", async () => {
    const { result, emit } = await connected();
    await act(() => result.current.loadMessages("b2"));
    expect(result.current.handoffs.b2?.id).toBe(12);

    await act(() => result.current.answerQuestion(result.current.handoffs.b2, 0));
    const post = calls.find((c) => c.method === "POST" && c.url.endsWith("/api/bots/b2/messages"));
    expect(post?.body).toEqual({ text: "Done", answer: { messageId: 12, option: 0 } });
    expect(result.current.handoffs.b2).toBeUndefined();
    expect(result.current.messages.b2.find((m) => m.id === 12)?.question?.picked).toBe(0);

    await emit({ type: "message", message: handoff });
    expect(result.current.messages.b2).toHaveLength(2);
  });

  it("restores the handoff when answering fails", async () => {
    const { result } = await connected();
    await act(() => result.current.loadMessages("b2"));
    failAnswer = true;

    let error: unknown;
    await act(async () => {
      await result.current.answerQuestion(handoff, 0).catch((e) => (error = e));
    });
    expect((error as Error).message).toBe("boom");
    expect(result.current.handoffs.b2?.id).toBe(12);
    expect(result.current.messages.b2.find((m) => m.id === 12)?.question?.picked).toBeNull();
  });

  it("clears a handoff once the user sends a later message", async () => {
    const { result, emit } = await connected();
    await emit({ type: "message", message: handoff });
    await emit({ type: "message", message: { id: 20, botId: "b2", role: "user", text: "later", at: 5 } });
    expect(result.current.handoffs.b2).toBeUndefined();
  });

  it("gets the screen link with the auth header, never in the URL", async () => {
    const { result } = await connected();
    let url = "";
    await act(async () => {
      url = await result.current.fetchScreenUrl("b2");
    });
    expect(url).toBe("https://bots.example.com/screen/6901/?token=voxl");
    const req = calls.find((c) => c.url.endsWith("/screen"));
    expect(req?.headers.Authorization).toMatch(/^Basic /);
    expect(url).not.toContain("hunter2");
    expect(req?.url).not.toContain("hunter2");
  });

  it("creates, edits, and deletes routines", async () => {
    const { result } = await connected();
    await act(async () => {
      await result.current.createRoutine("b2", { name: " Digest ", cron: "0 9 * * *", instruction: "Sum up", enabled: true });
      await result.current.updateRoutine(routine, { name: "Digest", cron: "0 8 * * 1-5", instruction: "Sum up", enabled: false });
      await result.current.updateRoutine(routine, { name: "Digest", cron: "0 9 * * *", instruction: "Sum up", enabled: true });
      await result.current.deleteRoutine("r1");
    });
    const routineCalls = calls.filter((c) => c.url.includes("routine")).map((c) => [c.method, c.url.slice(BASE.length), c.body]);
    expect(routineCalls).toEqual([
      ["POST", "/api/bots/b2/routines", { name: "Digest", cron: "0 9 * * *", instruction: "Sum up", enabled: true }],
      ["PATCH", "/api/routines/r1", { cron: "0 8 * * 1-5", enabled: false }],
      ["DELETE", "/api/routines/r1", undefined],
    ]);
  });

  it("swaps a saved password for a session token and stops storing the password", async () => {
    loginToken = TOKEN;
    const { result } = await connected();
    const login = calls.find((c) => c.url.endsWith("/api/auth/login"));
    expect(login?.body).toEqual({ password: "hunter2", session: "token", label: "SuperBot app" });
    expect(saveCredentials).toHaveBeenCalledWith({ baseUrl: BASE, token: TOKEN });
    const state = calls.find((c) => c.url.endsWith("/api/state"));
    expect(state?.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect((connectSse as jest.Mock).mock.calls[0][1]).toEqual({ Authorization: `Bearer ${TOKEN}` });

    await act(() => result.current.logout());
    expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/api/auth/logout") && c.headers.Authorization === `Bearer ${TOKEN}`)).toBe(true);
    expect(clearCredentials).toHaveBeenCalled();
  });

  it("signs in with a one-time code", async () => {
    loginToken = TOKEN;
    (loadSavedCredentials as jest.Mock).mockImplementation(async () => null);
    const hook = await renderHook(() => useSuperBot(), { wrapper: SuperBotProvider });
    await waitFor(() => expect(hook.result.current.ready).toBe(true));
    let error: unknown;
    await act(async () => {
      await hook.result.current.login(BASE, "sbc_bad").catch((e) => (error = e));
    });
    expect((error as Error).message).toBe("Wrong password.");
    await act(() => hook.result.current.login(BASE, " sbc_good "));
    const login = calls.filter((c) => c.url.endsWith("/api/auth/login")).pop();
    expect(login?.body).toEqual({ code: "sbc_good", session: "token", label: "SuperBot app" });
    expect(login?.headers.Authorization).toBeUndefined();
    expect(saveCredentials).toHaveBeenCalledWith({ baseUrl: BASE, token: TOKEN });
    expect(hook.result.current.api).not.toBeNull();
  });

  it("keeps using the password on servers from before sign-in", async () => {
    const { result } = await connected();
    expect(saveCredentials).not.toHaveBeenCalled();
    expect(calls.find((c) => c.url.endsWith("/api/state"))?.headers.Authorization).toMatch(/^Basic /);
    let error: unknown;
    await act(async () => {
      await result.current.login(BASE, "sbc_code").catch((e) => (error = e));
    });
    expect((error as Error).message).toMatch("doesn't support sign-in codes");
  });

  it("forgets a session the server ended", async () => {
    loginToken = TOKEN;
    (loadSavedCredentials as jest.Mock).mockImplementation(async () => ({ baseUrl: BASE, token: "sbs_revoked" }));
    const hook = await renderHook(() => useSuperBot(), { wrapper: SuperBotProvider });
    await waitFor(() => expect(hook.result.current.ready).toBe(true));
    expect(hook.result.current.api).toBeNull();
    expect(hook.result.current.error).toBe("Your session ended. Sign in again.");
    expect(clearCredentials).toHaveBeenCalled();
  });

  it("doesn't mark chats read for read-only users", async () => {
    permissions = ["account", "read", "review"];
    bobUnread = true;
    const { result } = await connected();
    await waitFor(() => expect(result.current.canWrite).toBe(false));
    await act(() => result.current.loadMessages("b2"));
    expect(calls.some((c) => c.url.endsWith("/read"))).toBe(false);
  });
});
