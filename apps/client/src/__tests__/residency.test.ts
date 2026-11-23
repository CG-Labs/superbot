import { reportFileName, reportLabel, residencyLines } from "../residency";
import type { MyResidency } from "../types";

const AT = Date.UTC(2026, 10, 22);

function view(over: Partial<MyResidency> = {}): MyResidency {
  return {
    pin: { on: "user", region: "gb-lon", pinnedAt: AT, reference: "DPA-2026-014" },
    ownPin: null,
    status: "kept",
    machine: { id: "m1", state: "running", region: "gb-lon", inRegion: true },
    backups: { kept: 3, inRegion: 3, outside: 0 },
    modelRoutes: { inRegion: true, gap: null },
    reports: ["user"],
    ...over,
  };
}

describe("residencyLines (ADR 0168)", () => {
  it("says nothing when nothing pins your data", () => {
    expect(residencyLines(view({ pin: null }))).toEqual({ lines: [], warnings: [] });
  });

  it("says where your own pinned data is", () => {
    expect(residencyLines(view())).toEqual({
      lines: [
        "Your data is pinned to gb-lon under DPA-2026-014, since 2026-11-22.",
        "Your computer is in gb-lon.",
        "All 3 of your computer's backups are in gb-lon.",
        "Your Bots use AI models in gb-lon only.",
      ],
      warnings: [],
    });
  });

  it("names your team's pin, with its reference only when the server sent it, and your own as well", () => {
    const team = view({ pin: { on: "team", region: "de-fra-2", pinnedAt: AT, team: { id: "t1", name: "Acme" } }, ownPin: { region: "de-fra-2", pinnedAt: AT, reference: "DPA-bea" }, machine: null, backups: { kept: 0, inRegion: 0, outside: 0 } });
    expect(residencyLines(team).lines).toEqual([
      "Your team, Acme, has its data pinned to de-fra-2, since 2026-11-22.",
      "Your own data is also pinned to de-fra-2 under DPA-bea.",
      "Your Bots use AI models in de-fra-2 only.",
    ]);
  });

  it("names the team a pin was kept from when you left it, never its reference (ADR 0171)", () => {
    const kept = view({ pin: { on: "user", region: "gb-lon", pinnedAt: AT, keptFrom: { team: { id: "t1", name: "Acme" } } } });
    expect(residencyLines(kept).lines[0]).toBe("Your data is pinned to gb-lon, kept from Acme's pin when you left it, since 2026-11-22.");
    const gone = view({ pin: { on: "user", region: "gb-lon", pinnedAt: AT, keptFrom: { team: { id: "t1", name: null } } } });
    expect(residencyLines(gone).lines[0]).toBe("Your data is pinned to gb-lon, kept from your former team's pin when you left it, since 2026-11-22.");
    const back = view({ pin: { on: "team", region: "gb-lon", pinnedAt: AT, team: { id: "t1", name: "Acme" } }, ownPin: { region: "gb-lon", pinnedAt: AT, keptFrom: { team: { id: "t1", name: "Acme" } } } });
    expect(residencyLines(back).lines[1]).toBe("Your own data is also pinned to gb-lon, kept from Acme's pin when you left it.");
  });

  it("says a kept pin ends by itself once your computer and backups are gone, when the server says so (ADR 0205)", () => {
    const ENDS = "That pin ends by itself once your computer and its backups are gone.";
    const kept = (endsWhenDataGone?: boolean) => view({ pin: { on: "user", region: "gb-lon", pinnedAt: AT, keptFrom: { team: { id: "t1", name: "Acme" }, endsWhenDataGone } } });
    expect(residencyLines(kept(true)).lines[1]).toBe(ENDS);
    expect(residencyLines(kept(false)).lines).not.toContain(ENDS);
    expect(residencyLines(kept()).lines).not.toContain(ENDS);
    const back = view({ pin: { on: "team", region: "gb-lon", pinnedAt: AT, team: { id: "t1", name: "Acme" } }, ownPin: { region: "gb-lon", pinnedAt: AT, keptFrom: { team: { id: "t1", name: "Acme" }, endsWhenDataGone: true } } });
    expect(residencyLines(back).lines[2]).toBe(ENDS);
    expect(residencyLines(view()).lines).not.toContain(ENDS);
  });

  it("warns about data outside the region and runs held back for want of a model there", () => {
    const { warnings } = residencyLines(
      view({ status: "data_outside", machine: { id: "m1", state: "running", region: "de-fra-2", inRegion: false }, backups: { kept: 4, inRegion: 3, outside: 1 }, modelRoutes: { inRegion: false, gap: "open routing" } }),
    );
    expect(warnings).toEqual([
      "Your computer is in de-fra-2, not gb-lon. Your admins see a warning about it.",
      "1 of your computer's 4 backups are outside gb-lon. Your admins see a warning about it.",
      "Your plan has no AI model in gb-lon, so your Bots don't run until your admin adds one. Nothing is sent outside the region instead.",
    ]);
    const onHost = (hostRegion: string | null) => residencyLines(view({ status: "data_outside", machine: { id: "m1", state: "running", region: "gb-lon", inRegion: false, host: "b", hostRegion } })).warnings[0];
    expect(onHost("de-fra-2")).toBe("Your computer is on a server in de-fra-2, not gb-lon. Your admins see a warning about it.");
    expect(onHost(null)).toBe("Your computer is on a server with no data region set, so nothing shows it is in gb-lon. Your admins see a warning about it.");
    const host = residencyLines(view({ status: "data_outside" }));
    expect(host.warnings).toEqual(["Some of your data is outside gb-lon. Your admins see a warning about it."]);
  });

  it("says where the server's own copy of your account and chats is, when the server says (ADR 0184)", () => {
    expect(residencyLines(view({ serverData: { region: "gb-lon", inRegion: true } })).lines).toContain("SuperBot's own copy of your account and chats is in gb-lon.");
    const elsewhere = residencyLines(view({ serverData: { region: "de-fra-2", inRegion: false } }));
    expect(elsewhere.lines).toContain("SuperBot's own copy of your account and chats isn't in gb-lon; it is in de-fra-2. Your agreement says where it is.");
    expect(elsewhere.warnings).toEqual([]);
    expect(residencyLines(view({ serverData: { region: null, inRegion: false } })).lines).toContain("SuperBot's own copy of your account and chats isn't in gb-lon. Your agreement says where it is.");
    const backups = residencyLines(view({ serverData: { region: "gb-lon", inRegion: false, backupsInRegion: false } }));
    expect(backups.lines).toContain("SuperBot's own copy of your account and chats is in gb-lon, but its backups aren't kept there. Your agreement says where it is.");
    expect(residencyLines(view()).lines.some((l) => l.includes("SuperBot's own copy"))).toBe(false);
  });

  it("warns, once, when the server holds pins to its own region and isn't in yours (ADR 0184)", () => {
    const held = residencyLines(view({ status: "data_outside", serverData: { region: "de-fra-2", inRegion: false, backupsInRegion: true, required: true } }));
    expect(held.warnings).toEqual(["SuperBot's own copy of your account and chats isn't in gb-lon; it is in de-fra-2. Your admins see a warning about it."]);
    expect(held.lines.some((l) => l.includes("SuperBot's own copy"))).toBe(false);
  });
});

describe("chats in the region's own database (ADR 0215)", () => {
  it("says chats are kept in the region and leaves them out of the server's copy", () => {
    const held = residencyLines(view({ serverData: { region: "de-fra-2", inRegion: false }, chats: { store: true, inRegion: true } }));
    expect(held.lines).toContain("Your chats are kept in gb-lon, in a database of their own there.");
    expect(held.lines).toContain("SuperBot's own copy of your account isn't in gb-lon; it is in de-fra-2. Your agreement says where it is.");
    expect(held.warnings).toEqual([]);
  });

  it("says when the move is done but older backups elsewhere still hold copies", () => {
    const done = residencyLines(view({ serverData: { region: "de-fra-2", inRegion: false }, chats: { store: true, inRegion: false, moving: false, earlierBackups: 2 } }));
    expect(done.lines).toContain("Your chats are kept in gb-lon, in a database of their own there.");
    expect(done.lines).toContain("2 backups from before they moved still hold earlier copies in another region until they are deleted.");
    expect(done.lines.some((l) => l.includes("being moved"))).toBe(false);
    expect(done.lines).toContain("SuperBot's own copy of your account isn't in gb-lon; it is in de-fra-2. Your agreement says where it is.");
    const one = residencyLines(view({ chats: { store: true, inRegion: false, moving: false, earlierBackups: 1 } }));
    expect(one.lines).toContain("A backup from before they moved still holds earlier copies in another region until it is deleted.");
  });

  it("says when they are still moving, and says nothing without a store", () => {
    const moving = residencyLines(view({ serverData: { region: "de-fra-2", inRegion: false }, chats: { store: true, inRegion: false } }));
    expect(moving.lines).toContain("Your chats are being moved to gb-lon's own database.");
    expect(moving.lines).toContain("SuperBot's own copy of your account and chats isn't in gb-lon; it is in de-fra-2. Your agreement says where it is.");
    const none = residencyLines(view({ serverData: { region: "gb-lon", inRegion: true }, chats: { store: false, inRegion: true } }));
    expect(none.lines.some((l) => l.startsWith("Your chats"))).toBe(false);
    expect(none.lines).toContain("SuperBot's own copy of your account and chats is in gb-lon.");
  });
});

describe("reports", () => {
  it("labels each and names its file", () => {
    expect(reportLabel("user")).toBe("Download your report");
    expect(reportLabel("team")).toBe("Download the team's report");
    expect(reportFileName("team", "superbot-residency-team-t1-20261123.md")).toBe("superbot-residency-team-t1-20261123.md");
    expect(reportFileName("user", null, AT)).toBe("superbot-residency-user-20261122.md");
    expect(reportFileName("user", "../evil.md", AT)).toBe("superbot-residency-user-20261122.md");
  });
});
