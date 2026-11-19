import { SuperBotApi } from "../api";

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
});
