import {
  actorLabel,
  auditQuery,
  csvFileName,
  DECISIONS,
  decisionSummary,
  detailsPretty,
  detailsText,
  eventFields,
  eventText,
  KINDS,
  linkedFilters,
  localDay,
  nameFrom,
  NO_FILTERS,
  pivotsFor,
  signInLabel,
  targetLabel,
} from "../audit";
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

  it("sends the Bot, session, and on-behalf-of filters as the server names them", () => {
    const q = auditQuery({ ...NO_FILTERS, outcome: "denied", bot: " b1 ", session: "s1", onBehalfOf: "ada@example.com" });
    expect(q).toBe("outcome=denied&bot=b1&session=s1&onBehalfOf=ada%40example.com");
  });

  it("only offers kinds of action the server accepts", () => {
    // The server's rule (audit.rs `Filter::from_query`): up to 20 names, lowercase, digits, `_` and `.`, optionally ending in `.*`.
    for (const { value } of KINDS.filter((k) => k.value)) {
      const names = value.split(",");
      expect(names.length).toBeLessThanOrEqual(20);
      for (const n of names) expect(n).toMatch(/^[a-z0-9_.]{1,64}$|^[a-z0-9_.]{1,64}\.\*$/);
    }
    expect(DECISIONS).toBe("approval.approved,approval.denied,approval.expired");
    expect(new Set(KINDS.map((k) => k.label)).size).toBe(KINDS.length);
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

describe("linkedFilters", () => {
  it("takes the filters a link may set, trimmed, and nothing else", () => {
    expect(linkedFilters({ bot: " b1 ", session: "", person: ["ada@example.com", "x"], outcome: "failure", from: "2026-01-01" })).toEqual({
      bot: "b1",
      person: "ada@example.com",
    });
    expect(linkedFilters({})).toEqual({});
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

  it("lists every field of an event, labelled, and leaves out empty ones", () => {
    const e = ev({
      id: 7,
      actorId: "u1",
      actorName: "Ada",
      actorEmail: "ada@example.com",
      actorRole: "member",
      authMethod: "sso",
      idp: "entra",
      idpProvider: "work",
      sessionId: "s1",
      botId: "b1",
      onBehalfOf: "u2",
      targetType: "bot",
      targetId: "b1",
      ip: "192.0.2.1",
    });
    const fields = Object.fromEntries(eventFields(e, { nameOf: (id) => (id === "u2" ? "Bo" : id), botName: (id) => (id === "b1" ? "Scout" : undefined) }));
    expect(fields).toMatchObject({
      UTC: "1970-01-01T00:00:00.000Z",
      Outcome: "success",
      Who: "Ada (user)",
      "User id": "u1",
      Email: "ada@example.com",
      Role: "member",
      "Sign-in": "SSO",
      IdP: "entra (work)",
      Session: "s1",
      "On behalf of": "Bo (u2)",
      "About Bot": "Scout (b1)",
      Target: "bot b1",
      IP: "192.0.2.1",
      Event: "7",
    });
    expect(fields).not.toHaveProperty("User agent");
    expect(Object.fromEntries(eventFields(ev({ actorKind: "system", actorId: "scheduler", onBehalfOf: "u9", botId: "b9" })))).toMatchObject({
      Part: "scheduler",
      "On behalf of": "u9",
      "About Bot": "b9",
    });
  });

  it("sums up approval decisions, and only those", () => {
    const d = { subject: "git push", tool: "Bash", class: "push", note: null, rule: "r1" };
    expect(decisionSummary(ev({ action: "approval.denied", details: d }))).toEqual({
      verdict: "Denied",
      lines: [
        ["Call", "git push"],
        ["Tool", "Bash"],
        ["Kind", "push"],
        ["Saved as rule", "r1"],
      ],
    });
    // As the server sends it (`RunScope::covers_text`): one reason per kind of call the run may repeat.
    const forRun = decisionSummary(ev({ action: "approval.approved", details: { runId: "run1", covers: ["pushes to origin", "", "installs packages"] } }));
    expect(forRun).toEqual({ verdict: "Approved for the rest of the run", lines: [["Covers", "pushes to origin; installs packages"]] });
    expect(decisionSummary(ev({ action: "approval.approved", details: { runId: "run1", covers: [] } }))?.verdict).toBe("Approved");
    expect(decisionSummary(ev({ action: "approval.approved", details: {} }))?.verdict).toBe("Approved");
    expect(decisionSummary(ev({ action: "approval.expired", details: null }))).toEqual({ verdict: "Expired: nobody answered, so it was denied", lines: [] });
    expect(decisionSummary(ev({ action: "approval.requested" }))).toBeNull();
  });

  it("offers fresh filters that follow an event's action, person, Bots, session, and on-behalf-of", () => {
    const pivots = pivotsFor(ev({ actorId: "u1", actorName: "Ada", botId: "b1", sessionId: "s1", onBehalfOf: "u2" }), {
      nameOf: (id) => (id === "u2" ? "Bo" : id),
      botName: (id) => (id === "b1" ? "Scout" : undefined),
    });
    expect(pivots.map((p) => [p.label, auditQuery(p.filters)])).toEqual([
      ["Only bot.created", "action=bot.created"],
      ["Everything by Ada", "actor=user%3Au1"],
      ["Everything about Scout", "bot=b1"],
      ["Everything in this session", "session=s1"],
      ["Everything done for Bo", "onBehalfOf=u2"],
    ]);
    const byBot = pivotsFor(ev({ actorKind: "bot", actorId: "b2", botId: "b1" }));
    expect(byBot.map((p) => p.label)).toEqual(["Only bot.created", "Everything about b1", "Everything about b2"]);
    expect(pivotsFor(ev({ actorKind: "bot", actorId: "b1", botId: "b1" })).map((p) => p.label)).toEqual(["Only bot.created", "Everything about b1"]);
  });

  it("pretty-prints details and the whole event", () => {
    expect(detailsPretty(ev({ details: {} }))).toBe("");
    expect(detailsPretty(ev({ details: { a: 1 } }))).toBe('{\n  "a": 1\n}');
    expect(JSON.parse(eventText(ev({ id: 3 })))).toMatchObject({ id: 3, action: "bot.created" });
  });

  it("names the export as the server does", () => {
    expect(csvFileName(new Date("2026-11-19T13:04:05.678Z"))).toBe("superbot-audit-20261119-130405.csv");
  });
});
