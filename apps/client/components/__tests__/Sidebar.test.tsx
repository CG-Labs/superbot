import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { Sidebar } from "../Sidebar";
import type { Me } from "../../src/types";

jest.mock("../BotAvatar", () => ({ BotAvatar: () => null }));

const ALL = ["account", "read", "review", "write", "approve", "admin"];
const mockCtx: Record<string, unknown> = {};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

function setup(me: Me) {
  Object.assign(mockCtx, {
    bots: [],
    activeId: null,
    filter: "",
    setFilter: jest.fn(),
    showHidden: false,
    setShowHidden: jest.fn(),
    me,
    handoffs: {},
    approvals: [],
    canWrite: true,
  });
  const props = {
    onSelectBot: jest.fn(),
    onNewBot: jest.fn(),
    onLogout: jest.fn(),
    onOpenApprovals: jest.fn(),
    onOpenUsers: jest.fn(),
    onOpenAudit: jest.fn(),
    onOpenAccessReview: jest.fn(),
    onOpenRoles: jest.fn(),
    onOpenServiceAccounts: jest.fn(),
    onOpenConsole: jest.fn(),
  };
  return props;
}

describe("Sidebar admin entries", () => {
  it("shows admins the users, roles, service accounts, the audit log, the access review, and a link to the admin console", async () => {
    const props = setup({ name: "Owner", role: "admin", permissions: ALL });
    const user = userEvent.setup();
    await render(<Sidebar {...props} />);
    await user.press(screen.getByRole("link", { name: "Admin console" }));
    expect(props.onOpenConsole).toHaveBeenCalledTimes(1);
    await user.press(screen.getByText("Audit log"));
    expect(props.onOpenAudit).toHaveBeenCalledTimes(1);
    await user.press(screen.getByText("Access review"));
    expect(props.onOpenAccessReview).toHaveBeenCalledTimes(1);
    await user.press(screen.getByText("Users"));
    expect(props.onOpenUsers).toHaveBeenCalledTimes(1);
    await user.press(screen.getByText("Roles"));
    expect(props.onOpenRoles).toHaveBeenCalledTimes(1);
    await user.press(screen.getByText("Service accounts"));
    expect(props.onOpenServiceAccounts).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("link", { name: "Finish server setup" })).toBeNull();
  });

  it("points admins at the setup wizard while it waits for them", async () => {
    const onOpenSetup = jest.fn();
    const props = { ...setup({ name: "Owner", role: "admin", permissions: ALL }), onOpenSetup };
    const user = userEvent.setup();
    await render(<Sidebar {...props} />);
    await user.press(screen.getByRole("link", { name: "Finish server setup" }));
    expect(onOpenSetup).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["member", { name: "Alex", role: "member", permissions: ["account", "read", "review", "write", "approve"] }],
    ["a delegate with users.manage", { name: "Del", role: "member", permissions: ["account", "read", "review", "write", "approve", "users.manage"] }],
    ["read-only", { name: "Rae", role: "readonly", permissions: ["account", "read", "review"] }],
    ["a Bot", { name: "Scout", role: "bot", permissions: ["account", "read", "write"] }],
    ["a server from before roles", { name: "You" }],
  ] as [string, Me][])("shows %s none of them", async (_, me) => {
    await render(<Sidebar {...setup(me)} onOpenSetup={jest.fn()} />);
    expect(screen.queryByRole("link", { name: "Finish server setup" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Admin console" })).toBeNull();
    expect(screen.queryByText("Admin console ↗")).toBeNull();
    expect(screen.queryByText("Audit log")).toBeNull();
    expect(screen.queryByText("Access review")).toBeNull();
    expect(screen.queryByText("Users")).toBeNull();
    expect(screen.queryByText("Roles")).toBeNull();
    expect(screen.queryByText("Service accounts")).toBeNull();
    expect(screen.getByText("Approvals")).toBeOnTheScreen();
  });
});

describe("Sidebar plan entry (ADR 0042)", () => {
  it("shows everyone their plan when the server sells plans", async () => {
    const onOpenPlan = jest.fn();
    const user = userEvent.setup();
    await render(<Sidebar {...setup({ name: "Alex", role: "member", permissions: ["account", "read", "write"] })} onOpenPlan={onOpenPlan} />);
    await user.press(screen.getByText("Plan"));
    expect(onOpenPlan).toHaveBeenCalledTimes(1);
  });

  it("hides it when billing isn't set up", async () => {
    await render(<Sidebar {...setup({ name: "Owner", role: "admin", permissions: ALL })} />);
    expect(screen.queryByText("Plan")).toBeNull();
  });
});

describe("Sidebar secrets entry (ADR 0044)", () => {
  it.each([
    ["an admin", { name: "Owner", role: "admin", permissions: ALL }],
    ["a member", { name: "Alex", role: "member", permissions: ["account", "read", "write"] }],
    ["a read-only person", { name: "Rae", role: "readonly", permissions: ["account", "read", "review"] }],
  ] as [string, Me][])("opens their own secrets for %s", async (_, me) => {
    const onOpenSecrets = jest.fn();
    const user = userEvent.setup();
    await render(<Sidebar {...setup(me)} onOpenSecrets={onOpenSecrets} />);
    await user.press(screen.getByText("Your secrets"));
    expect(onOpenSecrets).toHaveBeenCalledTimes(1);
  });
});
