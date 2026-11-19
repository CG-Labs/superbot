import { isAllowedScreenNavigation, resolveScreenUrl, serverOrigin } from "../screen";

describe("serverOrigin", () => {
  it("keeps scheme, host, and port only", () => {
    expect(serverOrigin("https://Bots.Example.com/")).toBe("https://bots.example.com");
    expect(serverOrigin("http://127.0.0.1:3000/prefix?x=1")).toBe("http://127.0.0.1:3000");
    expect(serverOrigin("bots.example.com")).toBe("http://bots.example.com");
  });

  it("rejects user info in the address", () => {
    expect(() => serverOrigin("https://user:pass@bots.example.com")).toThrow();
  });
});

describe("resolveScreenUrl", () => {
  const base = "https://bots.example.com";

  it("resolves the server's relative link against its origin", () => {
    expect(resolveScreenUrl(base, "/screen/6901/?token=abc")).toBe("https://bots.example.com/screen/6901/?token=abc");
    expect(resolveScreenUrl(`${base}/api-prefix/`, "/screen/6902/?token=t")).toBe(
      "https://bots.example.com/screen/6902/?token=t",
    );
  });

  it("accepts an absolute link on the same origin", () => {
    expect(resolveScreenUrl(base, "https://bots.example.com/screen/6901/?token=abc")).toBe(
      "https://bots.example.com/screen/6901/?token=abc",
    );
  });

  it("never puts the server password in the link", () => {
    const url = resolveScreenUrl(base, "/screen/6901/?token=abc");
    expect(url).not.toContain("@");
    expect(url).not.toMatch(/password|authorization/i);
  });

  it.each([
    "https://evil.example/screen/6901/?token=abc",
    "https://bots.example.com.evil.example/screen/6901/",
    "//evil.example/screen/6901/",
    "javascript:alert(1)",
    "/api/state",
    "/screen/abc/",
    "/screen/6901/\\evil",
    "screen/6901/",
  ])("rejects %s", (url) => {
    expect(() => resolveScreenUrl(base, url)).toThrow();
  });
});

describe("isAllowedScreenNavigation", () => {
  const origin = "https://bots.example.com";

  it("allows the server's own pages and inline documents", () => {
    expect(isAllowedScreenNavigation(origin, "https://bots.example.com/screen/6901/?token=a")).toBe(true);
    expect(isAllowedScreenNavigation(origin, "about:blank")).toBe(true);
    expect(isAllowedScreenNavigation(origin, "blob:https://bots.example.com/123")).toBe(true);
  });

  it("blocks other sites, including look-alike hosts", () => {
    expect(isAllowedScreenNavigation(origin, "https://evil.example/")).toBe(false);
    expect(isAllowedScreenNavigation(origin, "https://bots.example.com.evil.example/")).toBe(false);
    expect(isAllowedScreenNavigation(origin, "http://bots.example.com/")).toBe(false);
  });
});
