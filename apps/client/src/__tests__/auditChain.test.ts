import { archiveCheckLine, chainLines, checkpointLine, exportLine, exportLines, shortHash, timestampLine, verificationLine } from "../auditChain";
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

  it("says when the last check covered only part of the log", () => {
    const partial = { ...chainState().verification!, range: { from: 10, to: 20 } };
    expect(verificationLine(partial)).toMatchObject({ tone: "warn", text: expect.stringContaining("Intact, events 10 to 20 only") });
    expect(verificationLine({ ...partial, range: { from: 10, to: null } }).text).toContain("from event 10 only");
    expect(verificationLine({ ...partial, range: { from: null, to: 20 } }).text).toContain("up to event 20 only");
    expect(verificationLine({ ...partial, range: null }).tone).toBe("ok");
    expect(verificationLine({ ...partial, ok: false, firstBroken: { id: 12, reason: "contents" } }).text).toContain("Broken at event 12 (contents), events 10 to 20 only");
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

  it("says how the S3 archive's objects are locked", () => {
    const archive = { endpoint: "https://s3.example", bucket: "audit", prefix: "prod", lock: "compliance" as const, retainDays: 400, batchSeconds: 300, lastObject: { key: "prod/x.jsonl", version: "v1", events: 3, lockMode: "compliance", retainUntil: 1_900_000_000_000 } };
    const on = { enabled: true as const, kind: "s3", sink: "s3://audit/prod", delivered: 40, pending: 0, deliveredAt: null, failing: false, lastError: null, archive };
    expect(exportLine(on)).toMatchObject({ tone: "ok", text: expect.stringContaining("last object locked (compliance) until") });
    expect(exportLine({ ...on, archive: { ...archive, lock: "off" as const, lastObject: null } })).toMatchObject({ tone: "warn", text: expect.stringContaining("objects not locked") });
  });

  it("shows a SIEM and an archive side by side, each with its own state", () => {
    const archive = { endpoint: "https://s3.example", bucket: "audit", prefix: "prod", lock: "bucket" as const, retainDays: null, batchSeconds: 300, lastObject: null };
    const siem = { kind: "webhook", sink: "https://siem.example", delivered: 30, pending: 13, deliveredAt: null, failing: true, lastError: "answered HTTP 503" };
    const s3 = { kind: "s3", sink: "s3://audit/prod", delivered: 43, pending: 0, deliveredAt: null, failing: false, lastError: null, archive };
    const both = { enabled: true as const, ...siem, sinks: [siem, s3] };
    expect(exportLines(both)).toEqual([
      { label: "SIEM export", text: "Failing to https://siem.example: answered HTTP 503. 13 waiting.", tone: "bad" },
      { label: "Archive", text: "s3://audit/prod: 0 behind, last delivery never", tone: "ok" },
    ]);
    expect(chainLines(chainState({ export: both })).map((l) => l.label).slice(-2)).toEqual(["SIEM export", "Archive"]);
    expect(exportLines({ enabled: false })).toEqual([exportLine({ enabled: false })]);
  });

  it("names each of several SIEMs", () => {
    const sink = { kind: "webhook", delivered: 43, pending: 0, deliveredAt: null, failing: false, lastError: null };
    const splunk = { ...sink, name: "splunk", sink: "https://splunk.example" };
    const sentinel = { ...sink, name: "sentinel", sink: "https://sentinel.example", failing: true, lastError: "answered HTTP 401", pending: 5 };
    const lines = exportLines({ enabled: true as const, ...sentinel, sinks: [splunk, sentinel] });
    expect(lines.map((l) => [l.label, l.tone])).toEqual([
      ["SIEM export (splunk)", "ok"],
      ["SIEM export (sentinel)", "bad"],
    ]);
    expect(lines[1].text).toBe("Failing to https://sentinel.example: answered HTTP 401. 5 waiting.");
  });

  it("lists every part in order", () => {
    expect(chainLines(chainState()).map((l) => l.label)).toEqual(["Last check", "Head", "Last checkpoint", "Timestamps", "SIEM export"]);
  });

  it("shows the archive's part of the last check, new objects only or all of them (ADR 0183)", () => {
    const v = chainState().verification!;
    expect(archiveCheckLine(v)).toBeNull();
    const archive = { ok: true, objects: 3, skipped: 40, head: { id: 43, hash: HASH }, after: 37, problems: 0, firstProblem: null };
    expect(archiveCheckLine({ ...v, archive })).toMatchObject({ label: "Archive check", tone: "ok", text: expect.stringContaining("Intact to event 43: 3 new objects read") });
    expect(archiveCheckLine({ ...v, archive: { ...archive, after: null, objects: 43 } })!.text).toContain("all 43 objects read");
    const broken = { ...archive, ok: false, problems: 2, firstProblem: { key: null, id: 37, reason: "mismatch", error: "the log was rebuilt" } };
    expect(archiveCheckLine({ ...v, archive: broken })).toMatchObject({ tone: "bad", text: "Broken, 2 problems. First: mismatch at event 37: the log was rebuilt" });
    expect(archiveCheckLine({ ...v, archive: { ...broken, problems: 0, firstProblem: null, error: "s3:ListBucketVersions" } })!.text).toContain("First: s3:ListBucketVersions");
    expect(chainLines(chainState({ verification: { ...v, archive } })).map((l) => l.label).slice(0, 2)).toEqual(["Last check", "Archive check"]);
  });
});
