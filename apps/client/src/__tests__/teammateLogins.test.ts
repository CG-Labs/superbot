import { SuperBotApi } from "../api";
import { lastLink, LineReader, LoginError, loginLine, plainOutput, streamLogin, teammateLoginPath, type StreamXhr } from "../teammateLogins";
import type { LoginEvent } from "../types";

const BASE = "https://bots.example.com";

/** A stand-in XMLHttpRequest whose body the test grows. */
class FakeXhr implements StreamXhr {
  opened: [string, string] | null = null;
  headers: Record<string, string> = {};
  sent: string | null = null;
  aborted = false;
  responseText = "";
  status = 0;
  onprogress: (() => void) | null = null;
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;
  open(method: string, url: string) {
    this.opened = [method, url];
  }
  setRequestHeader(name: string, value: string) {
    this.headers[name] = value;
  }
  send(body: string) {
    this.sent = body;
  }
  abort() {
    this.aborted = true;
    this.onabort?.();
  }
  grow(status: number, text: string) {
    this.status = status;
    this.responseText += text;
    this.onprogress?.();
  }
}

describe("teammates' own logins (ADR 0062)", () => {
  it("names the owner's machine in the path", () => {
    expect(teammateLoginPath("u 1", "harness-logins")).toBe("/api/machine/teammate/u%201/harness-logins");
  });

  it("reads each line once, only when it's whole", () => {
    const r = new LineReader();
    expect(r.read('{"type":"started","loginId":"l1"}\n{"type":"out')).toEqual([{ type: "started", loginId: "l1" }]);
    expect(r.read('{"type":"started","loginId":"l1"}\n{"type":"output","text":"hi"}\n\nnot json\n')).toEqual([{ type: "output", text: "hi" }]);
    expect(r.read('{"type":"started","loginId":"l1"}\n{"type":"output","text":"hi"}\n\nnot json\n')).toEqual([]);
  });

  it("shows a terminal's text without its codes, and its last link", () => {
    const shown = "\u001b[1mOpen\u001b[0m https://example.com/a?x=1\r\n\u001b]0;title\u0007then https://example.com/b\r\n";
    expect(plainOutput(shown)).toBe("Open https://example.com/a?x=1\nthen https://example.com/b\n");
    expect(lastLink(shown)).toBe("https://example.com/b");
    expect(lastLink("no link")).toBeNull();
  });

  it("says plainly what each state means for your runs, and that the owner's login is never yours", () => {
    expect(loginLine({ state: "logged_in", serverKey: false }, "Ada")).toBe("Logged in with your own account on Ada's computer.");
    expect(loginLine({ state: "logging_in", serverKey: false }, "Ada")).toBe("A login is running.");
    expect(loginLine({ state: "logged_out", serverKey: true }, "Ada")).toMatch(/server-wide key/);
    expect(loginLine({ state: "logged_out", serverKey: false }, "Ada")).toMatch(/refused until you log in\. Ada's login is never used for you/);
    expect(loginLine(undefined, "Ada")).toMatch(/refused/);
  });

  it("names this server when the owner's Bots run here (ADR 0064)", () => {
    expect(loginLine({ state: "logged_in", serverKey: false }, "Ada", "server")).toBe("Logged in with your own account for Ada's Bots on this server.");
    expect(loginLine({ state: "logged_out", serverKey: true }, "Ada", "server")).toBe("Not logged in. A server-wide key runs it for you for Ada's Bots on this server.");
    const out = loginLine({ state: "logged_out", serverKey: false }, "Ada", "server");
    expect(out).toMatch(/for Ada's Bots on this server are refused until you log in\. Ada's login is never used for you/);
    expect(out).not.toMatch(/computer/);
  });

  it("streams a login's events as they come, and stops when asked", async () => {
    const xhr = new FakeXhr();
    const seen: LoginEvent[] = [];
    const s = streamLogin(() => xhr, `${BASE}/x`, { Authorization: "Bearer t" }, "claude", (e) => seen.push(e));
    expect(xhr.opened).toEqual(["POST", `${BASE}/x`]);
    expect(xhr.headers).toEqual({ Authorization: "Bearer t" });
    expect(JSON.parse(xhr.sent!)).toEqual({ harness: "claude" });
    xhr.grow(200, '{"type":"started","loginId":"l1"}\n{"type":"output","text":"Paste');
    expect(seen).toEqual([{ type: "started", loginId: "l1" }]);
    xhr.grow(200, ' it"}\n');
    expect(seen[1]).toEqual({ type: "output", text: "Paste it" });
    s.stop();
    expect(xhr.aborted).toBe(true);
    await expect(s.done).resolves.toBeUndefined();
  });

  it("fails with the server's words when it refuses", async () => {
    const xhr = new FakeXhr();
    const s = streamLogin(() => xhr, `${BASE}/x`, {}, "claude", () => {});
    xhr.status = 404;
    xhr.responseText = '{"error":"Machine not found"}';
    xhr.onload?.();
    await expect(s.done).rejects.toEqual(new LoginError("Machine not found", 404));
    const dropped = new FakeXhr();
    const d = streamLogin(() => dropped, `${BASE}/x`, {}, "claude", () => {});
    dropped.onerror?.();
    await expect(d.done).rejects.toThrow("dropped");
  });

  it("goes to the owner's machine as you", async () => {
    const realFetch = globalThis.fetch;
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ harnesses: {} }) }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const api = new SuperBotApi({ baseUrl: BASE, token: "sbs_" + "a".repeat(64) });
      await api.teammateLogins("u1");
      await api.teammateLoginInput("u1", "l1", "code");
      await api.stopTeammateLogin("u1", "l1");
      await api.teammateLogout("u1", "claude");
      const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
      expect(calls.map(([url, init]) => `${init.method} ${url.slice(BASE.length)}`)).toEqual([
        "GET /api/machine/teammate/u1/harness-logins",
        "POST /api/machine/teammate/u1/harness-login/l1/input",
        "DELETE /api/machine/teammate/u1/harness-login/l1",
        "DELETE /api/machine/teammate/u1/harness-logins/claude",
      ]);
      expect(JSON.parse(calls[1][1].body as string)).toEqual({ text: "code" });
      const xhr = new FakeXhr();
      api.startTeammateLogin("u1", "codex", () => {}, () => xhr);
      expect(xhr.opened).toEqual(["POST", `${BASE}/api/machine/teammate/u1/harness-login`]);
      expect(xhr.headers.Authorization).toMatch(/^Bearer sbs_/);
      expect(xhr.headers["Content-Type"]).toBe("application/json");
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
