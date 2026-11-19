import { appUrl, CODE_TTLS, formatExpiry, inviteLink, inviteMessage, relativeTime, takeInviteCode } from "../invite";

const CODE = "sbc_" + "ab".repeat(32);

describe("invites", () => {
  it("offers 1 hour, 24 hours, and 7 days, all within the server's limit", () => {
    expect(CODE_TTLS.map((t) => t.minutes)).toEqual([60, 1440, 10080]);
  });

  it("points at the web client on the server, with the code in the fragment", () => {
    expect(appUrl("https://bots.example.com/")).toBe("https://bots.example.com/app/");
    expect(inviteLink("https://bots.example.com", CODE)).toBe(`https://bots.example.com/app/#code=${CODE}`);
  });

  it("writes a message with the app URL, the server URL, the code, and its expiry", () => {
    const now = 1_000_000;
    const msg = inviteMessage({ name: "Alex", serverUrl: "https://bots.example.com", code: CODE, expiresAt: now + 24 * 3600_000, now });
    expect(msg).toContain("Hi Alex");
    expect(msg).toContain(`https://bots.example.com/app/#code=${CODE}`);
    expect(msg).toContain("open https://bots.example.com/app/ and enter the server URL https://bots.example.com");
    expect(msg).toContain(`one-time code: ${CODE}`);
    expect(msg).toContain("expires in 24 hours");
  });

  it("formats times", () => {
    expect(formatExpiry(60_000 * 60, 0)).toBe("in 60 minutes");
    expect(formatExpiry(7 * 24 * 3600_000, 0)).toBe("in 7 days");
    expect(formatExpiry(0, 1)).toBe("expired");
    expect(relativeTime(null)).toBe("Never");
    expect(relativeTime(0, 1)).toBe("Never");
    expect(relativeTime(1000, 1000 + 5 * 60_000)).toBe("5 min ago");
    expect(relativeTime(1000, 1000 + 3 * 24 * 3600_000)).toBe("3 d ago");
  });

  it("takes a code from the link and clears it from the address bar", () => {
    const replaceState = jest.fn();
    const loc = { hash: `#code=${CODE}`, pathname: "/app/", search: "?x=1" };
    expect(takeInviteCode(loc, { replaceState })).toBe(CODE);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/app/?x=1");
  });

  it("ignores anything that isn't a sign-in code, but still clears it", () => {
    const replaceState = jest.fn();
    expect(takeInviteCode({ hash: "#code=hunter2", pathname: "/app/", search: "" }, { replaceState })).toBeNull();
    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(takeInviteCode({ hash: "", pathname: "/", search: "" }, { replaceState })).toBeNull();
    expect(takeInviteCode({ hash: "#section", pathname: "/", search: "" }, { replaceState })).toBeNull();
    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(takeInviteCode(undefined, undefined)).toBeNull();
  });
});
