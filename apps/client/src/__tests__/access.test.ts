import { botAccess, hasAccess, sharingLabel } from "../access";

describe("Bot access", () => {
  it("follows what the server says", () => {
    expect(hasAccess({ access: "view" }, "view", true)).toBe(true);
    expect(hasAccess({ access: "view" }, "operate", true)).toBe(false);
    expect(hasAccess({ access: "operate" }, "operate", true)).toBe(true);
    expect(hasAccess({ access: "operate" }, "manage", true)).toBe(false);
    expect(hasAccess({ access: "manage" }, "manage", true)).toBe(true);
  });

  it("never lets a read-only role act, whatever the Bot says", () => {
    expect(hasAccess({ access: "manage" }, "operate", false)).toBe(false);
    expect(hasAccess({ access: "manage" }, "view", false)).toBe(true);
  });

  it("falls back to the role on servers from before Bot ACLs", () => {
    expect(botAccess({}, true)).toBe("manage");
    expect(botAccess(undefined, false)).toBe("view");
    expect(hasAccess({}, "manage", true)).toBe(true);
  });

  it("says who can see a Bot", () => {
    expect(sharingLabel({ visibility: "shared", owner: { id: "u1", name: "Ada" } }, "u1")).toBe("Shared with everyone · owned by you");
    expect(sharingLabel({ visibility: "private", owner: { id: "u2", name: "Grace" } }, "u1")).toBe("Private · owned by Grace");
    expect(sharingLabel({ visibility: "private", owner: null })).toBe("Private");
  });
});
