import React from "react";
import { act, render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { RoleRequestsCard } from "../RoleRequestsCard";
import { ApiError } from "../../src/api";
import type { MyRoleRequests, RequestableRole, RoleRequest } from "../../src/types";

const NOW = Date.UTC(2026, 10, 23, 12);

const ONCALL: RequestableRole = {
  id: "r1",
  name: "On-call",
  description: "Production access during an incident",
  base: "member",
  permissions: ["machines.manage", "audit.view"],
  teamPermissions: ["machines.manage"],
  maxDays: 1,
  maxHours: 24,
  org: { ok: true, why: null },
  team: { ok: true, why: null },
};

const PENDING: RoleRequest = {
  id: "q1",
  role: { id: "r1", name: "On-call", maxDays: 1, permissions: [], applies: [] },
  scope: "org",
  team: null,
  user: { id: "me", name: "Me", email: "me@example.com" },
  hours: 8,
  reason: "Incident 41",
  status: "pending",
  createdAt: NOW,
  expiresAt: NOW + 7 * 86_400_000,
  decidedAt: null,
  decidedBy: null,
  note: null,
  grantedUntil: null,
};

const mine = (v: Partial<MyRoleRequests> = {}): MyRoleRequests => ({ requestable: [ONCALL], team: { id: "t1", name: "Ops" }, requests: [], pendingDays: 7, maxPending: 5, ...v });

function fakeApi(v: MyRoleRequests) {
  return {
    myRoleRequests: jest.fn(async () => v),
    requestRole: jest.fn(async () => PENDING),
    withdrawRoleRequest: jest.fn(async () => ({ ...PENDING, status: "cancelled" as const })),
  };
}

describe("RoleRequestsCard (ADR 0209)", () => {
  beforeEach(() => jest.spyOn(Date, "now").mockReturnValue(NOW));
  afterEach(() => jest.restoreAllMocks());

  it("shows nothing when no role may be requested", async () => {
    const api = fakeApi(mine({ requestable: [] }));
    const { toJSON } = await render(<RoleRequestsCard api={api} />);
    await waitFor(() => expect(toJSON()).toBeNull());
    expect(api.myRoleRequests).toHaveBeenCalled();
  });

  it("shows nothing on a server from before requests", async () => {
    const api = fakeApi(mine());
    api.myRoleRequests.mockRejectedValueOnce(new ApiError("Not found", 404));
    const { toJSON } = await render(<RoleRequestsCard api={api} />);
    await waitFor(() => expect(toJSON()).toBeNull());
    expect(api.myRoleRequests).toHaveBeenCalled();
  });

  it("shows a skeleton while it loads, then a retry that loads it", async () => {
    const api = fakeApi(mine());
    let fail: (e: Error) => void = () => {};
    api.myRoleRequests.mockImplementationOnce(() => new Promise((_, reject) => (fail = reject)));
    await render(<RoleRequestsCard api={api} />);
    expect(screen.getByRole("heading", { name: "Request access" })).toBeOnTheScreen();
    expect(screen.getByRole("progressbar", { name: "Loading the roles you may request" })).toBeOnTheScreen();
    await act(async () => fail(new ApiError("HTTP 500", 500)));
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load the roles you may request. The server had a problem. Try again in a moment.");
    await userEvent.setup().press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Production access during an incident")).toBeOnTheScreen();
    expect(api.myRoleRequests).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says when no role may be requested beside your requests, and why an ask failed", async () => {
    const api = fakeApi(mine({ requestable: [], requests: [PENDING] }));
    await render(<RoleRequestsCard api={api} />);
    expect(await screen.findByRole("heading", { name: "No role may be requested now" })).toBeOnTheScreen();
    expect(screen.getByRole("heading", { name: "Your requests" })).toBeOnTheScreen();

    const asking = fakeApi(mine());
    asking.requestRole.mockRejectedValueOnce(new ApiError("You have 5 requests waiting already.", 409));
    const u = userEvent.setup();
    await render(<RoleRequestsCard api={asking} />);
    await u.type(await screen.findByLabelText("Why you need it"), "Incident 43");
    await u.press(screen.getByRole("button", { name: "Ask for it" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("You have 5 requests waiting already.");
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });

  it("asks for a role for a while, with a reason, within its limit", async () => {
    const api = fakeApi(mine());
    const u = userEvent.setup();
    await render(<RoleRequestsCard api={api} />);
    expect(await screen.findByText("Production access during an incident")).toBeTruthy();
    expect(screen.getByText("Adds machines.manage, audit.view. At most 1 day.")).toBeTruthy();
    expect(screen.queryByRole("radio", { name: "3 days" })).toBeNull();
    // No reason, no request.
    expect(screen.getByLabelText("Ask for it")).toBeDisabled();
    await u.press(screen.getByRole("radio", { name: "In Ops" }));
    expect(screen.getByText("Adds machines.manage. At most 1 day.")).toBeTruthy();
    await u.press(screen.getByRole("radio", { name: "4 hours" }));
    await u.type(screen.getByLabelText("Why you need it"), "Incident 42");
    await u.press(screen.getByLabelText("Ask for it"));
    await waitFor(() => expect(api.requestRole).toHaveBeenCalledWith({ role: "r1", scope: "team", hours: 4, reason: "Incident 42" }));
    expect(await screen.findByText(/An admin decides; it lapses in 7 days/)).toBeTruthy();
  });

  it("says why a role can't be asked for in a scope", async () => {
    const api = fakeApi(mine({ requestable: [{ ...ONCALL, org: { ok: false, why: "It's based on member, and you're read-only." }, team: { ok: false, why: "You're read-only, so it would do nothing in a team." } }] }));
    await render(<RoleRequestsCard api={api} />);
    expect(await screen.findByText("It's based on member, and you're read-only.")).toBeTruthy();
    expect(screen.getByLabelText("Ask for it")).toBeDisabled();
  });

  it("lists your requests and withdraws a pending one", async () => {
    const approved: RoleRequest = { ...PENDING, id: "q0", status: "approved", grantedUntil: NOW + 3 * 3_600_000 };
    const api = fakeApi(mine({ requests: [PENDING, approved, { ...PENDING, id: "q9", status: "denied", note: "Use the runbook" }] }));
    const u = userEvent.setup();
    await render(<RoleRequestsCard api={api} />);
    expect(await screen.findByText("Waiting for an admin · lapses in 7 days")).toBeTruthy();
    expect(screen.getByText(/^Approved · ends in 3 hours/)).toBeTruthy();
    expect(screen.getByText("Denied: Use the runbook")).toBeTruthy();
    expect(screen.getAllByLabelText("Withdraw request for On-call")).toHaveLength(1);
    await u.press(screen.getByLabelText("Withdraw request for On-call"));
    await waitFor(() => expect(api.withdrawRoleRequest).toHaveBeenCalledWith("q1"));
  });

  it("says when a role needs two approvers, and where a request is (ADR 0320)", async () => {
    const first = { by: { id: "u2", name: "Ada" }, at: NOW, hours: 4, note: null };
    const api = fakeApi(mine({ requestable: [{ ...ONCALL, approvals: 2 }], requests: [{ ...PENDING, approvals: 2, firstApproval: first }] }));
    const u = userEvent.setup();
    await render(<RoleRequestsCard api={api} />);
    expect(await screen.findByText("Adds machines.manage, audit.view. At most 1 day. Two people approve it before it starts.")).toBeTruthy();
    expect(screen.getByText("Approved once, waiting for a second approver · lapses in 7 days")).toBeTruthy();
    await u.type(screen.getByLabelText("Why you need it"), "Rotate keys");
    await u.press(screen.getByLabelText("Ask for it"));
    expect(await screen.findByText(/Two people approve it before it starts; it lapses in 7 days/)).toBeTruthy();
  });
});
