import { chainLines, checkpointLine, exportLine, shortHash, timestampLine, verificationLine } from "../auditChain";
import type { AuditChainState, AuditCheckpoint } from "../types";

const HASH = "ab".repeat(32);

const checkpoint = (c: Partial<AuditCheckpoint> = {}): AuditCheckpoint => ({
  id: 41,
  at: Date.UTC(2026, 10, 22, 12),
  seq: 40,
  hash: HASH,
  keyId: "0123456789abcdef",
  publicKey: "cd".repeat(32),
  signature: "ef".repeat(64),
  statement: "superbot-audit-checkpoint-v1",
  timestamp: { status: "stamped", tsa: "https://tsa.example", time: Date.UTC(2026, 10, 22, 12, 0, 1), tries: 0, error: null },
  ...c,
});

const chainState = (s: Partial<AuditChainState> = {}): AuditChainState => ({
  head: { id: 43, hash: HASH },
  events: 43,
  anchor: null,
  checkpoints: { everyMinutes: 60, count: 1, key: { id: "0123456789abcdef", publicKey: "cd".repeat(32), algorithm: "Ed25519" }, last: checkpoint(), behind: 2 },
  timestamps: { enabled: true, tsa: "https://tsa.example", trustAnchors: 1, stamped: 1, pending: 0, failing: false, failingSince: null, lastError: null, last: { checkpoint: 41, event: 42, time: Date.UTC(2026, 10, 22, 12, 0, 1), tsa: "https://tsa.example" } },
  export: { enabled: false },
  verification: { id: 44, at: Date.UTC(2026, 10, 22, 13), by: "audit", ok: true, reason: null, checked: 43, broken: 0, firstBroken: null },
  ...s,
});

describe("audit chain lines (ADR 0149)", () => {
  it("shortens hashes for comparing by eye", () => {
    expect(shortHash(HASH)).toBe("abababababab…");
    expect(shortHash(null)).toBe("—");
  });

  it("says whether the last check held, and where it broke", () => {
    expect(verificationLine(null)).toMatchObject({ tone: "dim", text: expect.stringContaining("Not checked yet") });
    expect(verificationLine(chainState().verification)).toMatchObject({ tone: "ok", text: expect.stringContaining("Intact: 43 events") });
    const broken = { ...chainState().verification!, ok: false, reason: "checkpoint", firstBroken: { id: 41, reason: "checkpoint" } };
    expect(verificationLine(broken)).toMatchObject({ tone: "bad", text: expect.stringContaining("Broken at event 41 (checkpoint)") });
  });

  it("names the last checkpoint, the head it signs and its key", () => {
    expect(checkpointLine(null, 0)).toMatchObject({ tone: "dim", text: "None yet (on request only)" });
    expect(checkpointLine(checkpoint(), 60).text).toContain("Event 41 signs event 40 (abababababab…)");
    expect(checkpointLine(checkpoint(), 60).text).toContain("key 0123456789abcdef");
  });

  it("shows timestamps as off, healthy, unanchored, or failing", () => {
    expect(timestampLine(chainState({ timestamps: { ...chainState().timestamps, enabled: false } }))).toMatchObject({ tone: "dim", text: "Off (AUDIT_TIMESTAMP_URL)" });
    expect(timestampLine(chainState())).toMatchObject({ tone: "ok", text: expect.stringContaining("by https://tsa.example") });
    expect(timestampLine(chainState({ timestamps: { ...chainState().timestamps, trustAnchors: 0, pending: 2 } }))).toMatchObject({ tone: "warn", text: expect.stringContaining("2 waiting (no CA set") });
    const failing = { ...chainState().timestamps, failing: true, lastError: "answered HTTP 500", pending: 3 };
    expect(timestampLine(chainState({ timestamps: failing }))).toMatchObject({ tone: "bad", text: "Failing at https://tsa.example: answered HTTP 500. 3 waiting." });
  });

  it("shows the SIEM export's lag", () => {
    expect(exportLine({ enabled: false })).toMatchObject({ tone: "dim" });
    const on = { enabled: true as const, kind: "webhook", sink: "https://siem.example", delivered: 40, pending: 3, deliveredAt: null, failing: false, lastError: null };
    expect(exportLine(on)).toMatchObject({ tone: "ok", text: "https://siem.example: 3 behind, last delivery never" });
    expect(exportLine({ ...on, failing: true, lastError: "refused" })).toMatchObject({ tone: "bad", text: expect.stringContaining("Failing to https://siem.example: refused") });
  });

  it("lists every part in order", () => {
    expect(chainLines(chainState()).map((l) => l.label)).toEqual(["Last check", "Head", "Last checkpoint", "Timestamps", "SIEM export"]);
  });
});
