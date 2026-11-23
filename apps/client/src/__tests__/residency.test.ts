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

  it("warns about data outside the region and runs held back for want of a model there", () => {
    const { warnings } = residencyLines(
      view({ status: "data_outside", machine: { id: "m1", state: "running", region: "de-fra-2", inRegion: false }, backups: { kept: 4, inRegion: 3, outside: 1 }, modelRoutes: { inRegion: false, gap: "open routing" } }),
    );
    expect(warnings).toEqual([
      "Your computer is in de-fra-2, not gb-lon. Your admins see a warning about it.",
      "1 of your computer's 4 backups are outside gb-lon. Your admins see a warning about it.",
      "Your plan has no AI model in gb-lon, so your Bots don't run until your admin adds one. Nothing is sent outside the region instead.",
    ]);
    const host = residencyLines(view({ status: "data_outside" }));
    expect(host.warnings).toEqual(["Some of your data is outside gb-lon. Your admins see a warning about it."]);
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
