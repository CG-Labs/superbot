import { endUnsent, forgetWords, keepWords, takeWords, unsentFor } from "../unsent";

describe("unsent", () => {
  it("keeps one store per session", () => {
    const session = {};
    keepWords(unsentFor(session), "b", "Ship it");
    expect(unsentFor(session).words).toEqual({ b: ["Ship it"] });
    expect(unsentFor({}).words).toEqual({});
  });

  it("keeps every failed message for a Bot, oldest first, and gives them back together", () => {
    const store = unsentFor({});
    keepWords(store, "b", "Ship it");
    keepWords(store, "b", "Then tag it");
    keepWords(store, "b", "Ship it");
    keepWords(store, "b", "Pull first", true);
    expect(takeWords(store, "b")).toBe("Pull first\n\nShip it\n\nThen tag it");
    expect(takeWords(store, "b")).toBeNull();
  });

  it("forgets a message once it's sent again", () => {
    const store = unsentFor({});
    keepWords(store, "b", "Ship it");
    keepWords(store, "b", "Then tag it");
    forgetWords(store, "b", "Ship it");
    expect(store.words).toEqual({ b: ["Then tag it"] });
    forgetWords(store, "b", "Then tag it");
    forgetWords(store, "a", "Nothing here");
    expect(store.words).toEqual({});
  });

  it("forgets a signed-out session", () => {
    const session = {};
    const store = unsentFor(session);
    keepWords(store, "b", "Ship it");
    store.retries.b = { body: "Ship it", toast: 1 };
    endUnsent(session);
    expect(store).toEqual({ words: {}, retries: {}, ended: true });
    keepWords(store, "b", "Late failure");
    expect(unsentFor(session)).toEqual({ words: {}, retries: {}, ended: true });
  });

  it("keeps nothing without a session", () => {
    const store = unsentFor(null);
    expect(store.ended).toBe(true);
    keepWords(store, "b", "Ship it");
    expect(store.words).toEqual({});
    expect(() => endUnsent(null)).not.toThrow();
  });
});
