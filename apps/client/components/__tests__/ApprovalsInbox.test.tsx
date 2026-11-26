import React from "react";
import { act, fireEvent, render, screen, userEvent } from "@testing-library/react-native";
import { ApprovalCard, ApprovalsInbox, runScopeText } from "../ApprovalsInbox";
import type { Approval } from "../../src/types";

const mockCtx: Record<string, unknown> = {};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));
jest.setTimeout(20_000);

const PUSH: Approval = {
  id: "a1",
  botId: "b1",
  harness: "claude",
  tool: "Bash",
  kind: "shell",
  subject: "git push origin main",
  class: "git_push",
  reason: "Pushes to a git remote",
  status: "pending",
  createdAt: 0,
  expiresAt: Date.now() + 10 * 60_000,
  runId: "r1",
  runScope: { covers: ["Pushes to a git remote"], exact: false },
};

const decideApproval = jest.fn(async () => {});

function as(role: "admin" | "member" | "readonly") {
  Object.assign(mockCtx, {
    bots: [{ id: "b1", name: "Scout", color: "#fff", shape: "waddle" }],
    decideApproval,
    can: (p: string) => (p === "approve" ? role !== "readonly" : p === "admin" ? role === "admin" : true),
    canOnBot: () => true,
  });
}

beforeAll(async () => {
  as("member");
  const { unmount } = await render(<ApprovalCard approval={PUSH} />);
  await unmount();
}, 60_000);
beforeEach(() => {
  decideApproval.mockClear();
  jest.useFakeTimers();
});
afterEach(() => jest.useRealTimers());

describe("ApprovalCard: approve for this run (ADR 0051)", () => {
  it("approves calls like this one for the rest of the run, and says what that covers", async () => {
    as("member");
    const user = userEvent.setup();
    await render(<ApprovalCard approval={PUSH} />);
    expect(screen.getByText("For this run, calls like this (Pushes to a git remote) won't ask again until the task ends. Nothing is saved as a rule.")).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Approve for this run" }));
    expect(decideApproval).toHaveBeenCalledWith("a1", true, false, "run");
  });

  it("still approves just this call", async () => {
    as("member");
    const user = userEvent.setup();
    await render(<ApprovalCard approval={PUSH} />);
    await user.press(screen.getByRole("button", { name: "Approve" }));
    expect(decideApproval).toHaveBeenCalledWith("a1", true, false, "once");
  });

  it("offers nothing more for a call that can only be approved once", async () => {
    as("member");
    await render(<ApprovalCard approval={{ ...PUSH, runScope: null, class: "shell_destructive" }} />);
    expect(screen.getByRole("button", { name: "Approve" })).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Approve for this run" })).toBeNull();
    expect(screen.queryByText(/For this run/)).toBeNull();
  });

  it("is never combined with remembering a rule", async () => {
    as("admin");
    const user = userEvent.setup();
    await render(<ApprovalCard approval={PUSH} />);
    expect(screen.getByRole("button", { name: "Approve for this run" })).toBeOnTheScreen();
    await act(async () => fireEvent(screen.getByRole("switch"), "valueChange", true));
    expect(screen.queryByRole("button", { name: "Approve for this run" })).toBeNull();
    await user.press(screen.getByRole("button", { name: "Approve" }));
    expect(decideApproval).toHaveBeenCalledWith("a1", true, true, "once");
  });

  it("is hidden from people who can't approve", async () => {
    as("readonly");
    await render(<ApprovalCard approval={PUSH} />);
    expect(screen.queryByRole("button", { name: "Approve for this run" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("shows the approval a notification linked to first, or says it's gone (ADR 0061)", async () => {
    as("member");
    const other = { ...PUSH, id: "a0", subject: "rm -rf build" };
    Object.assign(mockCtx, { approvals: [other, PUSH], policy: { mode: "ask" } });
    const { rerender } = await render(<ApprovalsInbox visible onClose={jest.fn()} focusId="a1" />);
    const subjects = screen.getAllByText(/git push origin main|rm -rf build/).map((n) => n.props.children);
    expect(subjects).toEqual(["git push origin main", "rm -rf build"]);
    expect(screen.queryByText(/isn't waiting anymore/)).toBeNull();
    await rerender(<ApprovalsInbox visible onClose={jest.fn()} focusId="gone" />);
    expect(screen.getByText(/That approval isn't waiting anymore/)).toBeOnTheScreen();
  });

  it("says you're all caught up when nothing waits, and names its close button", async () => {
    as("member");
    const onClose = jest.fn();
    Object.assign(mockCtx, { approvals: [], policy: { mode: "ask" } });
    await render(<ApprovalsInbox visible onClose={onClose} />);
    expect(screen.getByRole("heading", { name: "You're all caught up" })).toBeOnTheScreen();
    expect(screen.getByText(/Nothing is waiting for you/)).toBeOnTheScreen();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Close approvals" })));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("puts a failed answer into plain words", async () => {
    as("member");
    decideApproval.mockRejectedValueOnce(new TypeError("Failed to fetch") as never);
    await render(<ApprovalCard approval={PUSH} />);
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Approve" })));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't send your answer. Can't reach the server. Check your connection and try again.");
  });

  it("says when only the exact call is covered", () => {
    expect(runScopeText({ ...PUSH, runScope: { covers: ["Deletes outside the workspace"], exact: true } })).toBe(
      "For this run, this exact call won't ask again until the task ends. Nothing is saved as a rule.",
    );
    expect(runScopeText({ ...PUSH, runScope: { covers: ["Pushes to a git remote", "Installs software (npm install)"], exact: false } })).toContain(
      "calls like this (Pushes to a git remote; Installs software (npm install))",
    );
  });
});
