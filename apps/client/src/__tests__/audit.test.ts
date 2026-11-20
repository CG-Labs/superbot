import { actorLabel, auditQuery, csvFileName, detailsText, localDay, nameFrom, NO_FILTERS, signInLabel, targetLabel } from "../audit";
import type { AuditEvent } from "../types";

const ev = (e: Partial<AuditEvent>): AuditEvent => ({
  id: 1,
  at: 0,
  time: "1970-01-01T00:00:00.000Z",
  actorKind: "user",
  action: "bot.created",
  outcome: "success",
  ...e,
});

describe("auditQuery", () => {
  it("sends nothing when nothing is set", () => {
    expect(auditQuery(NO_FILTERS)).toBe("");
  });

  it("maps each filter to the server's parameters", () => {
    const q = auditQuery({ ...NO_FILTERS, action: " bot.*, auth.login_failed ", actor: "bot", method: "sso", outcome: "denied" });
    expect(q).toBe("action=bot.*%2C%20auth.login_failed&actor=bot&method=sso&outcome=denied");
  });

  it("finds a person by email or id, over the kind of actor", () => {
    expect(auditQuery({ ...NO_FILTERS, actor: "bot", person: "ada+work@example.com" })).toBe("actor=user%3Aada%2Bwork%40example.com");
    expect(auditQuery({ ...NO_FILTERS, person: "u42" })).toBe("actor=user%3Au42");
  });

  it("sends whole local days, To included", () => {
    const q = auditQuery({ ...NO_FILTERS, from: "2026-11-01", to: "2026-11-19" });
    expect(q).toBe(`from=${new Date(2026, 10, 1).getTime()}&to=${new Date(2026, 10, 20).getTime()}`);
    const one = auditQuery({ ...NO_FILTERS, from: "2026-11-19", to: "2026-11-19" });
    expect(one).toBe(`from=${new Date(2026, 10, 19).getTime()}&to=${new Date(2026, 10, 20).getTime()}`);
  });

  it("refuses dates that aren't real, and a range that runs backwards", () => {
    for (const bad of ["yesterday", "2026-02-30", "2026-13-01", "19-11-2026", "2026-1-5"]) {
      expect(() => auditQuery({ ...NO_FILTERS, from: bad })).toThrow("isn't a date");
    }
    expect(() => auditQuery({ ...NO_FILTERS, from: "2026-11-20", to: "2026-11-19" })).toThrow("From is after To");
    expect(localDay("  ")).toBeNull();
    expect(localDay("2024-02-29")).toBe(new Date(2024, 1, 29).getTime());
  });
});

describe("audit labels", () => {
  it("names who acted", () => {
    expect(actorLabel(ev({ actorName: "Ada", actorEmail: "ada@example.com" }))).toBe("Ada");
    expect(actorLabel(ev({ actorEmail: "ada@example.com" }))).toBe("ada@example.com");
    expect(actorLabel(ev({ actorKind: "bot", actorId: "b1" }), (id) => (id === "b1" ? "Scout" : undefined))).toBe("Scout");
    expect(actorLabel(ev({ actorKind: "bot" }))).toBe("A Bot");
    expect(actorLabel(ev({ actorKind: "system", actorId: "scheduler" }))).toBe("System · scheduler");
  });

  it("says how they signed in and whom a Bot acted for", () => {
    expect(signInLabel(ev({ actorRole: "admin", authMethod: "sso", idp: "entra", idpProvider: "work" }))).toBe("admin · SSO · entra (work)");
    expect(signInLabel(ev({ authMethod: "password" }))).toBe("Password (break-glass)");
    expect(signInLabel(ev({ authMethod: "magic" }))).toBe("magic");
    const events = [ev({ actorId: "u1", actorName: "Ada" })];
    expect(signInLabel(ev({ actorKind: "bot", authMethod: "bot_token", onBehalfOf: "u1" }), nameFrom(events))).toBe("Bot token · for Ada");
    expect(signInLabel(ev({ onBehalfOf: "u9" }), nameFrom(events))).toBe("for u9");
    expect(signInLabel(ev({}))).toBe("");
  });

  it("shows the target and any details", () => {
    expect(targetLabel(ev({ targetType: "bot", targetId: "b1" }))).toBe("bot b1");
    expect(targetLabel(ev({}))).toBe("");
    expect(detailsText(ev({ details: {} }))).toBe("");
    expect(detailsText(ev({ details: { name: "Scout" } }))).toBe('{"name":"Scout"}');
  });

  it("names the export as the server does", () => {
    expect(csvFileName(new Date("2026-11-19T13:04:05.678Z"))).toBe("superbot-audit-20261119-130405.csv");
  });
});
