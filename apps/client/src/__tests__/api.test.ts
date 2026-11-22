import { cookieSession, finishSignIn, MfaRequired, signIn, SuperBotApi } from "../api";

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

describe("access review (ADR 0099)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("exports the report with its digest, under the name the server gave it", async () => {
    const answer = (disposition: string | null) =>
      (globalThis.fetch = jest.fn(async () => ({ ok: true, status: 200, headers: new Headers(disposition ? { "content-disposition": disposition } : {}), text: async () => "a\r\n" })) as unknown as typeof fetch);
    const api = new SuperBotApi({ baseUrl: BASE, cookie: true });
    answer('attachment; filename="superbot-access-review-20261122-090500.csv"');
    expect(await api.accessReviewCsv("d 1")).toEqual({ csv: "a\r\n", fileName: "superbot-access-review-20261122-090500.csv" });
    expect((globalThis.fetch as jest.Mock).mock.calls[0][0]).toBe(`${BASE}/api/access-review/export.csv?digest=d%201`);
    answer(null);
    expect(await api.accessReviewCsv("d1")).toEqual({ csv: "a\r\n", fileName: null });
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

describe("SuperBotApi approvals (ADR 0051)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("approves once, for the rest of the run, or denies", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ id: "a1", status: "approved" }) }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const api = new SuperBotApi({ baseUrl: BASE, token: "sbs_" + "a".repeat(64) });
    const call = (url: string, body: unknown) =>
      expect(fetchMock).toHaveBeenLastCalledWith(`${BASE}${url}`, expect.objectContaining({ method: "POST", body: JSON.stringify(body) }));

    await api.decideApproval("a1", true, false, "run");
    call("/api/approvals/a1/approve", { remember: null, scope: "run" });
    await api.decideApproval("a1", true, true);
    call("/api/approvals/a1/approve", { remember: "bot", scope: "once" });
    await api.decideApproval("a1", false, false);
    call("/api/approvals/a1/deny", { remember: null, scope: "once" });
  });
});

describe("two-factor sign-in (ADR 0094)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const answer = (status: number, body: unknown) => {
    const fetchMock = jest.fn(async () => ({ ok: status < 400, status, json: async () => body }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  };

  it("turns the server's ask for a second factor into MfaRequired", async () => {
    answer(401, { error: "Enter the code from your authenticator app, or a recovery code.", mfa: "totp", challenge: "sbm_x" });
    const err = await signIn(BASE, "sbc_abc").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MfaRequired);
    expect((err as MfaRequired).challenge).toBe("sbm_x");
    expect((err as MfaRequired).mode).toBe("totp");
    expect((err as MfaRequired).setup).toBeNull();

    answer(401, { error: "Set it up.", mfa: "enroll", challenge: "sbm_y", secret: "ABCD", otpauthUrl: "otpauth://totp/x", qrSvg: "<svg/>" });
    const enrol = (await signIn(BASE, "pw").catch((e: unknown) => e)) as MfaRequired;
    expect(enrol.mode).toBe("enroll");
    expect(enrol.setup).toEqual({ secret: "ABCD", otpauthUrl: "otpauth://totp/x", qrSvg: "<svg/>" });

    answer(401, { error: "Wrong password." });
    await expect(signIn(BASE, "pw")).rejects.not.toBeInstanceOf(MfaRequired);
  });

  it("finishes with the challenge and a code, and passes recovery codes back", async () => {
    const token = "sbs_" + "a".repeat(64);
    const fetchMock = answer(200, { token, recoveryCodes: ["aaaaa-bbbbb"] });
    const r = await finishSignIn(BASE, "sbm_x", { totp: "123456" });
    expect(r).toEqual({ config: { baseUrl: BASE, token }, recoveryCodes: ["aaaaa-bbbbb"] });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({ challenge: "sbm_x", totp: "123456", session: "token", label: "SuperBot app" });

    answer(200, { token });
    expect((await finishSignIn(BASE, "sbm_x", { recoveryCode: "aaaaa-bbbbb" })).recoveryCodes).toBeNull();

    answer(401, { error: "That code is wrong. Try again.", mfa: "totp", challenge: "sbm_x" });
    await expect(finishSignIn(BASE, "sbm_x", { totp: "000000" })).rejects.toBeInstanceOf(MfaRequired);
    answer(401, { error: "Too many wrong codes. Sign in again." });
    await expect(finishSignIn(BASE, "sbm_x", { totp: "000000" })).rejects.toThrow("Too many wrong codes");
  });

  it("manages your own second factor and resets someone else's", async () => {
    const fetchMock = answer(200, {});
    const api = new SuperBotApi({ baseUrl: BASE, token: "sbs_t" });
    await api.mfaStatus();
    await api.mfaEnroll();
    await api.mfaConfirm("123456");
    await api.mfaNewRecoveryCodes({ recoveryCode: "aaaaa-bbbbb" });
    await api.mfaDisable({ totp: "654321" });
    await api.setMfaPolicy("admins");
    await api.resetUserMfa("u 1");
    const calls = (fetchMock.mock.calls as unknown as [string, RequestInit][]).map(([url, init]) => [init.method, url.slice(BASE.length), init.body ? JSON.parse(String(init.body)) : undefined]);
    expect(calls).toEqual([
      ["GET", "/api/auth/mfa", undefined],
      ["POST", "/api/auth/mfa/enroll", {}],
      ["POST", "/api/auth/mfa/confirm", { totp: "123456" }],
      ["POST", "/api/auth/mfa/recovery-codes", { recoveryCode: "aaaaa-bbbbb" }],
      ["POST", "/api/auth/mfa/disable", { totp: "654321" }],
      ["PUT", "/api/auth/mfa/policy", { require: "admins" }],
      ["DELETE", "/api/users/u%201/mfa", undefined],
    ]);
  });
});
