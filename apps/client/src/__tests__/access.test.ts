import { botAccess, hasAccess, keeperChoices, keeperQuestion, keptBy, sharingLabel, whereItRuns, whoseKeys } from "../access";

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
    expect(whoseKeys({ sharedBots: "isolated", visibility: "shared", owner: ada, teammateLogins: true }, "u2")).toBe(
      "For you it uses your own login or the server's keys and your access, never Ada's own",
    );
    expect(whoseKeys({ sharedBots: "isolated", visibility: "shared", owner: ada, teammateLogins: true }, "u1")).toBe(
      "Others' runs use their own login or the server's keys and their access, never your own",
    );
  });

  it("names the service account that keeps a Bot", () => {
    expect(keptBy({})).toBeNull();
    expect(keptBy({ serviceAccount: null })).toBeNull();
    expect(keptBy({ serviceAccount: { id: "sa1", name: "CI" } })).toBe("Kept by service account CI: its runs reach only what that account may");
  });

  it("offers the owner's accounts that could keep it, and the one that does (ADR 0229)", () => {
    const k = (id: string, name: string, extra = {}) => ({ id, name, role: "member" as const, status: "active" as const, keptBots: 0, full: false, ...extra });
    expect(keeperChoices({})).toEqual([{ value: "", label: "Nobody" }]);
    const keepers = [k("sa1", "CI"), k("sa2", "Nightly", { full: true }), k("sa3", "Old", { status: "disabled" })];
    expect(keeperChoices({ keepers })).toEqual([
      { value: "", label: "Nobody" },
      { value: "sa1", label: "CI" },
      { value: "sa3", label: "Old (disabled)" },
    ]);
    expect(keeperChoices({ keepers, serviceAccount: { id: "sa2", name: "Nightly", email: null } }).map((c) => c.value)).toEqual(["", "sa1", "sa2", "sa3"]);
  });

  it("says what handing a Bot over means, and taking it back", () => {
    expect(keeperQuestion("Ledger", "CI", null)).toEqual({ title: "Let CI keep Ledger?", body: expect.stringMatching(/^CI can rename it.*The Bot stays the owner's\.$/) });
    expect(keeperQuestion("Ledger", "CI", "Nightly").body).toMatch(/Nightly stops keeping it\.$/);
    expect(keeperQuestion("Ledger", null, "CI")).toEqual({ title: "Take Ledger back from CI?", body: expect.stringMatching(/its run there stops/) });
  });
});
