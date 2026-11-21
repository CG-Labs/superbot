import { approvalParam, focusFirst, MAX_RECIPIENTS, parseRecipients, parseSeconds, secondsLabel, testSummary, webhookUrlProblem } from "../notifications";
import type { Approval } from "../types";

const approval = (id: string) => ({ id, botId: "b1", tool: "Bash", subject: "git push", reason: "Pushes", status: "pending", expiresAt: 0 }) as unknown as Approval;

describe("notification helpers (ADR 0060)", () => {
  it("reads addresses split any way, once each", () => {
    expect(parseRecipients(" a@example.com,B@example.com\nb@example.com ; ")).toEqual({ to: ["a@example.com", "B@example.com"] });
    expect(parseRecipients("")).toEqual({ to: [] });
    expect(parseRecipients("ops@example.com nope")).toEqual({ problem: '"nope" isn\'t an email address.' });
    const many = Array.from({ length: MAX_RECIPIENTS + 1 }, (_, i) => `u${i}@example.com`).join(",");
    expect(parseRecipients(many)).toHaveProperty("problem");
  });

  it("reads seconds within the server's limits and says them plainly", () => {
    expect(parseSeconds(" 30 ", 600)).toEqual({ seconds: 30 });
    expect(parseSeconds("0", 600)).toEqual({ seconds: 0 });
    for (const bad of ["", "601", "1.5", "-1", "soon"]) expect(parseSeconds(bad, 600)).toHaveProperty("problem");
    expect([0, 1, 30, 60, 120, 90].map(secondsLabel)).toEqual(["right away", "1 second", "30 seconds", "1 minute", "2 minutes", "90 seconds"]);
  });

  it("checks webhook URLs the way the server does", () => {
    expect(webhookUrlProblem("https://hooks.slack.com/services/T0/B0/x")).toBeNull();
    expect(webhookUrlProblem("http://127.0.0.1:9000/hook")).toBeNull();
    expect(webhookUrlProblem("http://hooks.example.com/x")).toMatch(/https/);
    expect(webhookUrlProblem("https://u:p@hooks.example.com/x")).toMatch(/password/);
    expect(webhookUrlProblem("not a url")).toMatch(/URL/);
  });

  it("sums up a test", () => {
    expect(testSummary({ ok: true, results: [{ channel: "email", ok: true }, { channel: "webhook", ok: true }] })).toBe("Test sent: email and webhook.");
    expect(testSummary({ ok: false, results: [{ channel: "email", ok: true }, { channel: "webhook", ok: false, error: "the webhook answered HTTP 404" }] })).toBe(
      "Webhook failed: the webhook answered HTTP 404",
    );
  });

  it("takes the approval a link names, first in the list", () => {
    expect(approvalParam("a1b2c3d4")).toBe("a1b2c3d4");
    expect(approvalParam(["x1", "x2"])).toBe("x1");
    for (const bad of [undefined, "", "a b", "../x", "x".repeat(65)]) expect(approvalParam(bad)).toBeNull();
    const list = [approval("a"), approval("b"), approval("c")];
    expect(focusFirst(list, "c").list.map((a) => a.id)).toEqual(["c", "a", "b"]);
    expect(focusFirst(list, "z")).toEqual({ list, gone: true });
    expect(focusFirst(list, null)).toEqual({ list, gone: false });
  });
});
