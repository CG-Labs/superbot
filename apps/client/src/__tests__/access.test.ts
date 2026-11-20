import { botAccess, hasAccess, sharingLabel, whereItRuns, whoseKeys } from "../access";

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

  it("says where a Bot runs, when the server says", () => {
    const ada = { id: "u1", name: "Ada" };
    expect(whereItRuns({ owner: ada }, "u2")).toBeNull();
    expect(whereItRuns({ runsOn: "machine", owner: ada }, "u2")).toBe("Runs on Ada's computer");
    expect(whereItRuns({ runsOn: "machine", owner: ada }, "u1")).toBe("Runs on your computer");
    expect(whereItRuns({ runsOn: "server", owner: ada }, "u2")).toBe("Runs on this server, in Ada's folder");
    expect(whereItRuns({ runsOn: "nowhere", owner: null })).toBe("Can't run yet: its owner's computer isn't set up");
  });

  it("says whose keys a teammate's run uses", () => {
    const ada = { id: "u1", name: "Ada" };
    expect(whoseKeys({ visibility: "shared", owner: ada }, "u2")).toBeNull();
    expect(whoseKeys({ sharedBots: "isolated", visibility: "shared", owner: ada }, "u2")).toBe(
      "For you it uses the server's keys and your access, never Ada's own",
    );
    expect(whoseKeys({ sharedBots: "isolated", visibility: "shared", owner: ada }, "u1")).toBe(
      "Others' runs use the server's keys and their access, never your own",
    );
    expect(whoseKeys({ sharedBots: "isolated", visibility: "private", owner: ada }, "u1")).toBeNull();
  });
});
