import { cookieSession, SuperBotApi } from "../api";

const BASE = "https://bots.example.com";

describe("SuperBotApi.logout", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("gives up on a server that doesn't answer", async () => {
    let signal: AbortSignal | undefined;
    globalThis.fetch = jest.fn((_url: string, init: RequestInit = {}) => {
      signal = init.signal ?? undefined;
      return new Promise((_, reject) => signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    }) as unknown as typeof fetch;
    const api = new SuperBotApi({ baseUrl: BASE, token: "sbs_" + "a".repeat(64) });
    await expect(api.logout(10)).rejects.toThrow("aborted");
    expect(signal?.aborted).toBe(true);
  });

  it("sends nothing for a password config", async () => {
    globalThis.fetch = jest.fn() as unknown as typeof fetch;
    await new SuperBotApi({ baseUrl: BASE, password: "pw" }).logout();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("ends a cookie session with no Authorization header", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ ok: true }) }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await new SuperBotApi({ baseUrl: BASE, cookie: true }).logout();
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/api/auth/logout`, expect.objectContaining({ method: "POST", headers: {} }));
  });

  it("fails when the server couldn't end the session, but not when it was already gone", async () => {
    const answer = (status: number) =>
      (globalThis.fetch = jest.fn(async () => ({ ok: status < 400, status, json: async () => ({}) })) as unknown as typeof fetch);
    const api = new SuperBotApi({ baseUrl: BASE, cookie: true });
    answer(502);
    await expect(api.logout()).rejects.toThrow("Sign-out failed (502)");
    answer(401);
    await expect(api.logout()).resolves.toBeUndefined();
  });
});

describe("cookie sessions (ADR 0027)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const answer = (status: number, body: unknown) =>
    (globalThis.fetch = jest.fn(async () => ({ ok: status < 400, status, json: async () => body })) as unknown as typeof fetch);

  it("adopts the session the server's sign-in page left in this browser", async () => {
    answer(200, { user: { id: "u1" }, session: { id: "s1" }, landing: "/app/" });
    expect(await cookieSession(BASE)).toEqual({ baseUrl: BASE, cookie: true });
    expect(globalThis.fetch).toHaveBeenCalledWith(`${BASE}/api/auth/me`, expect.objectContaining({ credentials: "same-origin" }));
  });

  it("gives up on a server that doesn't answer, so sign-in still shows", async () => {
    let signal: AbortSignal | undefined;
    globalThis.fetch = jest.fn((_url: string, init: RequestInit = {}) => {
      signal = init.signal ?? undefined;
      return new Promise((_, reject) => signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    }) as unknown as typeof fetch;
    expect(await cookieSession(BASE, 10)).toBeNull();
    expect(signal?.aborted).toBe(true);
  });

  it("takes nothing without a session", async () => {
    answer(401, { error: "Login required" });
    expect(await cookieSession(BASE)).toBeNull();
    // ALLOW_NO_AUTH answers without a session: that is not a sign-in to keep.
    answer(200, { user: null, session: null });
    expect(await cookieSession(BASE)).toBeNull();
    globalThis.fetch = jest.fn(async () => Promise.reject(new Error("offline"))) as unknown as typeof fetch;
    expect(await cookieSession(BASE)).toBeNull();
  });

  it("sends no credentials of its own and treats a 401 as the session ending", async () => {
    answer(401, { error: "Login required" });
    const api = new SuperBotApi({ baseUrl: BASE, cookie: true });
    const ended = jest.fn();
    api.onSessionEnded = ended;
    await expect(api.verify()).rejects.toThrow("Login required");
    expect((globalThis.fetch as jest.Mock).mock.calls[0][1].headers).toEqual({});
    expect(ended).toHaveBeenCalled();
    expect(api.authHeaders()).toEqual({});
  });
});
