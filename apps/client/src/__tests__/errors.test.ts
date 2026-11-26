import { ApiError } from "../api";
import { errorText, friendlyError, OFFLINE_TEXT } from "../errors";

describe("friendlyError", () => {
  it("passes the server's own words through", () => {
    expect(friendlyError(new ApiError("Screens are off on this server.", 503))).toBe("Screens are off on this server.");
  });

  it.each([
    [401, "Your session ended. Sign in again."],
    [403, "You don't have access to that."],
    [404, "That isn't there anymore."],
    [429, "Too many tries. Wait a moment and try again."],
    [500, "The server had a problem. Try again in a moment."],
    [502, "The server had a problem. Try again in a moment."],
  ])("puts a bare HTTP %i into words", (status, text) => {
    expect(friendlyError(new ApiError(`HTTP ${status}`, status))).toBe(text);
  });

  it.each(["Failed to fetch", "Network request failed", "Load failed", "NetworkError when attempting to fetch resource."])(
    "says the server can't be reached for %j",
    (message) => {
      expect(friendlyError(new TypeError(message))).toBe(OFFLINE_TEXT);
    },
  );

  it("falls back for anything that isn't an error with words", () => {
    expect(friendlyError("nope")).toBe("Something went wrong. Try again.");
    expect(friendlyError(new Error("  "), "Couldn't load it.")).toBe("Couldn't load it.");
    expect(friendlyError(new ApiError("HTTP 418", 418), "Couldn't do it.")).toBe("Couldn't do it.");
  });
});

describe("errorText", () => {
  it("says what failed, then why", () => {
    expect(errorText(new TypeError("Failed to fetch"), "Couldn't load routines")).toBe(`Couldn't load routines. ${OFFLINE_TEXT}`);
    expect(errorText(null, "Couldn't load routines")).toBe("Couldn't load routines.");
    expect(errorText(null)).toBe("Something went wrong. Try again.");
  });
});
