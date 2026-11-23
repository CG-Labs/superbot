import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { AuditChainPanel } from "../AuditChainPanel";
import { AuditLog } from "../AuditLog";
import type { SuperBotApi } from "../../src/api";
import type { AuditChainState, AuditVerifyReport } from "../../src/types";

const HASH = "ab".repeat(32);

const state = (s: Partial<AuditChainState> = {}): AuditChainState => ({
  head: { id: 43, hash: HASH },
  events: 43,
  anchor: null,
  checkpoints: {
    everyMinutes: 60,
    count: 1,
    key: { id: "0123456789abcdef", publicKey: "cd".repeat(32), algorithm: "Ed25519" },
    last: {
      id: 41,
      at: Date.UTC(2026, 10, 22, 12),
      seq: 40,
      hash: HASH,
      keyId: "0123456789abcdef",
      publicKey: "cd".repeat(32),
      signature: "ef".repeat(64),
      statement: "superbot-audit-checkpoint-v1",
      timestamp: { status: "pending", tsa: "https://tsa.example", time: null, tries: 3, error: "answered HTTP 500" },
    },
    behind: 2,
  },
  timestamps: { enabled: true, tsa: "https://tsa.example", trustAnchors: 1, stamped: 0, pending: 1, failing: true, failingSince: 1, lastError: "answered HTTP 500", last: null },
  export: { enabled: true, kind: "webhook", sink: "https://siem.example", delivered: 40, pending: 3, deliveredAt: null, failing: false, lastError: null },
  verification: null,
  ...s,
});

const report = (r: Partial<AuditVerifyReport> = {}): AuditVerifyReport => ({
  ok: true,
  checked: 44,
  broken: 0,
  firstBroken: null,
  head: { id: 44, hash: HASH },
  checkpoints: { checked: 1, timestamped: 1, trustedTimestamps: 1, broken: 0, firstBroken: null },
  ...r,
});

function fakeApi(states: AuditChainState[], check: AuditVerifyReport) {
  const queue = [...states];
  return {
    auditChain: jest.fn(async () => queue.shift() ?? states[states.length - 1]),
    auditVerify: jest.fn(async () => check),
  };
}

describe("AuditChainPanel", () => {
  it("shows the head, the last checkpoint, timestamps failing, and the export's lag", async () => {
    const api = fakeApi([state()], report());
    await render(<AuditChainPanel api={api} />);
    expect(await screen.findByLabelText(/^Last check: Not checked yet/)).toBeOnTheScreen();
    expect(screen.getByLabelText("Head: Event 43 · abababababab…")).toBeOnTheScreen();
    expect(screen.getByLabelText(/^Last checkpoint: Event 41 signs event 40/)).toBeOnTheScreen();
    expect(screen.getByLabelText("Timestamps: Failing at https://tsa.example: answered HTTP 500. 1 waiting.")).toBeOnTheScreen();
    expect(screen.getByLabelText(/^SIEM export: https:\/\/siem.example: 3 behind/)).toBeOnTheScreen();
    expect(screen.getByText(/Checkpoint key 0123456789abcdef \(Ed25519\)/)).toBeOnTheScreen();
  });

  it("checks the chain on request, says what it found, and reloads", async () => {
    const after = state({ verification: { id: 45, at: Date.UTC(2026, 10, 22, 14), by: "Owner", ok: true, reason: null, checked: 44, broken: 0, firstBroken: null } });
    const api = fakeApi([state(), after], report());
    const user = userEvent.setup();
    await render(<AuditChainPanel api={api} />);
    await screen.findByLabelText(/^Last check: Not checked yet/);
    await user.press(screen.getByText("Check now"));
    expect(await screen.findByLabelText(/^This check: Intact: 44 events, 1 checkpoints, 1 timestamps/)).toBeOnTheScreen();
    expect(await screen.findByLabelText(/^Last check: Intact: 44 events/)).toBeOnTheScreen();
    expect(api.auditChain).toHaveBeenCalledTimes(2);
  });

  it("names where a check found the chain broken", async () => {
    const broken = report({ ok: false, broken: 1, firstBroken: { id: 41, reason: "checkpoint" }, checkpoints: { checked: 1, timestamped: 0, trustedTimestamps: null, broken: 1, firstBroken: { id: 41, reason: "head", error: "it signs event 40's hash, not the head it is sealed onto" } } });
    const api = fakeApi([state()], broken);
    const user = userEvent.setup();
    await render(<AuditChainPanel api={api} />);
    await screen.findByLabelText(/^Head:/);
    await user.press(screen.getByText("Check now"));
    expect(await screen.findByLabelText("This check: Broken at event 41 (checkpoint): it signs event 40's hash, not the head it is sealed onto")).toBeOnTheScreen();
  });

  it("says why the state couldn't load", async () => {
    const api = { auditChain: jest.fn(async () => Promise.reject(new Error("Admins only"))), auditVerify: jest.fn() };
    await render(<AuditChainPanel api={api as unknown as Pick<SuperBotApi, "auditChain" | "auditVerify">} />);
    expect(await screen.findByText("Admins only")).toBeOnTheScreen();
  });

  it("opens from the audit log's header, and only then asks for it", async () => {
    const api = { ...fakeApi([state()], report()), audit: jest.fn(async () => ({ events: [], nextBefore: null })), auditCsv: jest.fn() };
    const user = userEvent.setup();
    await render(<AuditLog api={api as unknown as SuperBotApi} onBack={jest.fn()} />);
    await screen.findByText("No events match.");
    expect(api.auditChain).not.toHaveBeenCalled();
    await user.press(screen.getByLabelText("The hash chain's state"));
    expect(await screen.findByTestId("audit-chain")).toBeOnTheScreen();
    expect(api.auditChain).toHaveBeenCalledTimes(1);
    await user.press(screen.getByLabelText("The hash chain's state"));
    expect(screen.queryByTestId("audit-chain")).toBeNull();
  });
});
