import { endUnsent, unsentFor } from "../unsent";

describe("unsent", () => {
  it("keeps one store per session", () => {
    const session = {};
    unsentFor(session).words.b = "Ship it";
    expect(unsentFor(session).words).toEqual({ b: "Ship it" });
    expect(unsentFor({}).words).toEqual({});
  });

  it("forgets a signed-out session", () => {
    const session = {};
    const store = unsentFor(session);
    store.words.b = "Ship it";
    store.retries.b = { body: "Ship it", toast: 1 };
    endUnsent(session);
    expect(store).toEqual({ words: {}, retries: {}, ended: true });
    expect(unsentFor(session).ended).toBe(true);
  });

  it("keeps nothing without a session", () => {
    const store = unsentFor(null);
    expect(store.ended).toBe(true);
    store.words.b = "Ship it";
    expect(unsentFor(null).words).toEqual({});
    expect(() => endUnsent(null)).not.toThrow();
  });
});
