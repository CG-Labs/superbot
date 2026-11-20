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

describe("audit log (ADR 0009, 0019)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const TOKEN = "sbs_" + "a".repeat(64);

  it("pages with the filter, a cursor, and a limit", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ events: [], nextBefore: null }) }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const api = new SuperBotApi({ baseUrl: BASE, token: TOKEN });
    await api.audit("action=bot.*");
    await api.audit("", 41, 50);
    expect(fetchMock.mock.calls.map((c) => (c as unknown as [string])[0])).toEqual([
      `${BASE}/api/audit?action=bot.*&limit=100`,
      `${BASE}/api/audit?before=41&limit=50`,
    ]);
  });

  it("fetches the CSV with the session's token, and says why the server refused it", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200, text: async () => "id,time\r\n" }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const api = new SuperBotApi({ baseUrl: BASE, token: TOKEN });
    expect(await api.auditCsv("actor=bot")).toBe("id,time\r\n");
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/api/audit/export.csv?actor=bot`, expect.objectContaining({ method: "GET", headers: { Authorization: `Bearer ${TOKEN}` } }));
    await api.auditCsv("");
    expect((fetchMock.mock.calls[1] as unknown as [string])[0]).toBe(`${BASE}/api/audit/export.csv`);

    globalThis.fetch = jest.fn(async () => ({ ok: false, status: 403, json: async () => ({ error: "Admins only" }) })) as unknown as typeof fetch;
    await expect(api.auditCsv("")).rejects.toMatchObject({ message: "Admins only", status: 403 });
  });
});

describe("personal secrets (ADR 0029, 0044)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("lists names, sends a value only to save it, and deletes by name", async () => {
    const fetchMock = jest.fn(async (_url: string, init: RequestInit = {}) => ({
      ok: true,
      status: 200,
      json: async () =>
        init.method === "GET"
          ? { secrets: [{ name: "OPENAI_API_KEY", createdAt: 1, updatedAt: 2, overrides: false }] }
          : init.method === "PUT"
            ? { secret: { name: "OPENAI_API_KEY", createdAt: 1, updatedAt: 3, overrides: false } }
            : { ok: true },
    }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const api = new SuperBotApi({ baseUrl: BASE, token: "sbs_" + "a".repeat(64) });
    expect(await api.mySecrets()).toEqual([{ name: "OPENAI_API_KEY", createdAt: 1, updatedAt: 2, overrides: false }]);
    expect(fetchMock).toHaveBeenLastCalledWith(`${BASE}/api/me/secrets`, expect.objectContaining({ method: "GET", body: undefined }));
    expect((await api.setMySecret("OPENAI_API_KEY", "sk-test")).updatedAt).toBe(3);
    expect(fetchMock).toHaveBeenLastCalledWith(
      `${BASE}/api/me/secrets/OPENAI_API_KEY`,
      expect.objectContaining({ method: "PUT", body: JSON.stringify({ value: "sk-test" }) }),
    );
    await api.deleteMySecret("A/../B");
    expect(fetchMock).toHaveBeenLastCalledWith(`${BASE}/api/me/secrets/A%2F..%2FB`, expect.objectContaining({ method: "DELETE" }));
  });
});

describe("SuperBotApi policy editor (ADR 0049)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("reads and patches the global or a Bot's policy, and adds and deletes rules", async () => {
    const policy = { mode: "ask", classes: { git_push: "deny" }, timeoutMinutes: 10 };
    const fetchMock = jest.fn(async (url: string, init: RequestInit = {}) => ({
      ok: true,
      status: 200,
      json: async () =>
        url.endsWith("/api/policy") && init.method === "PUT"
          ? { policy }
          : url.endsWith("/api/policy/rules")
            ? { id: "r1", botId: null, action: "deny", tool: "*", pattern: "rm *", note: null, at: 1 }
            : { policy, classes: [], rules: [], override: null },
    }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const api = new SuperBotApi({ baseUrl: BASE, token: "sbs_" + "a".repeat(64) });
    const call = (url: string, method: string, body?: unknown) =>
      expect(fetchMock).toHaveBeenLastCalledWith(`${BASE}${url}`, expect.objectContaining({ method, body: body === undefined ? undefined : JSON.stringify(body) }));

    expect((await api.policyView()).policy).toEqual(policy);
    call("/api/policy", "GET");
    await api.policyView("b1");
    call("/api/bots/b1/policy", "GET");
    expect(await api.patchGlobalPolicy({ timeoutMinutes: 15 })).toEqual(policy);
    call("/api/policy", "PUT", { timeoutMinutes: 15 });
    await api.patchBotPolicy("b1", { classes: { git_push: null }, timeoutMinutes: null });
    call("/api/bots/b1/policy", "PUT", { classes: { git_push: null }, timeoutMinutes: null });
    await api.resetBotPolicy("b1");
    call("/api/bots/b1/policy", "DELETE");
    expect((await api.addPolicyRule({ action: "deny", tool: "*", pattern: "rm *" })).id).toBe("r1");
    call("/api/policy/rules", "POST", { action: "deny", tool: "*", pattern: "rm *" });
    await api.deletePolicyRule("r/1");
    call("/api/policy/rules/r%2F1", "DELETE");
  });
});
