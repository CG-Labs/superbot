import React from "react";
import { act, fireEvent, render, screen, userEvent } from "@testing-library/react-native";
import { botRowLabel, Sidebar } from "../Sidebar";
import type { BotView, Me } from "../../src/types";

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

  it("shows a delegate with users.manage their own service accounts, and no admin entries (ADR 0182)", async () => {
    const props = setup({ name: "Del", role: "member", permissions: ["account", "read", "review", "write", "approve", "users.manage"] });
    const user = userEvent.setup();
    await render(<Sidebar {...props} />);
    await user.press(screen.getByText("Your service accounts"));
    expect(props.onOpenServiceAccounts).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Users")).toBeNull();
    expect(screen.queryByText("Roles")).toBeNull();
  });

  it.each([
    ["member", { name: "Alex", role: "member", permissions: ["account", "read", "review", "write", "approve"] }],
    ["an admin", { name: "Owner", role: "admin", permissions: ALL }],
    ["a server from before roles", { name: "You" }],
  ] as [string, Me][])("doesn't show %s the delegate's entry", async (_, me) => {
    await render(<Sidebar {...setup(me)} />);
    expect(screen.queryByText("Your service accounts")).toBeNull();
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

const bot = (id: string, name: string, extra: Partial<BotView> = {}): BotView => ({
  id,
  name,
  color: "#f5f5f5",
  shape: "waddle",
  harness: "claude",
  primary: false,
  hidden: false,
  unread: false,
  working: false,
  ...extra,
});
const MEMBER: Me = { name: "Alex", role: "member", permissions: ["account", "read", "review", "write", "approve"] };
const READONLY: Me = { name: "Rae", role: "readonly", permissions: ["account", "read", "review"] };

describe("Sidebar Bots for screen readers", () => {
  it("names each Bot with what's waiting on it", () => {
    expect(botRowLabel(bot("a", "Ada"), { unread: false, needsYou: false })).toBe("Ada");
    expect(botRowLabel(bot("a", "Ada", { working: true }), { unread: true, needsYou: false })).toBe("Ada, Working, unread");
    expect(botRowLabel(bot("a", "Ada", { working: true }), { unread: false, needsYou: true })).toBe("Ada, needs you on its screen");
  });

  it("labels the rows, marks the open one, and counts waiting approvals", async () => {
    const props = setup(MEMBER);
    Object.assign(mockCtx, {
      bots: [bot("m", "Main", { primary: true }), bot("a", "Ada", { unread: true }), bot("b", "Bob")],
      activeId: "b",
      handoffs: { m: { id: 1 } },
      approvals: [{ id: "x" }, { id: "y" }],
    });
    await render(<Sidebar {...props} />);
    expect(screen.getByRole("button", { name: "Main, needs you on its screen" })).not.toBeSelected();
    expect(screen.getByRole("button", { name: "Ada, unread" })).not.toBeSelected();
    expect(screen.getByRole("button", { name: "Bob" })).toBeSelected();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Ada, unread" })));
    expect(props.onSelectBot).toHaveBeenCalledWith("a");
    expect(screen.getByRole("button", { name: "Approvals, 2 waiting" })).toBeOnTheScreen();
  });
});

describe("Sidebar empty states", () => {
  it("offers a first Bot on phones when there are none", async () => {
    const props = setup(MEMBER);
    await render(<Sidebar {...props} compact />);
    expect(screen.getByRole("heading", { name: "No Bots yet" })).toBeOnTheScreen();
    // The empty state's button, beside the "+" at the top.
    const buttons = screen.getAllByRole("button", { name: "New Bot" });
    expect(buttons).toHaveLength(2);
    await act(async () => fireEvent.press(buttons[1]));
    expect(props.onNewBot).toHaveBeenCalledTimes(1);
  });

  it("tells read-only people where shared Bots appear, with nothing to press", async () => {
    const props = setup(READONLY);
    mockCtx.canWrite = false;
    await render(<Sidebar {...props} compact />);
    expect(screen.getByText("Bots shared with you show up here.")).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "New Bot" })).toBeNull();
  });

  it("leaves the first-Bot offer to the chat pane on wide windows", async () => {
    await render(<Sidebar {...setup(MEMBER)} />);
    expect(screen.queryByRole("heading", { name: "No Bots yet" })).toBeNull();
  });

  it("suggests more Bots beside the main one", async () => {
    const props = setup(MEMBER);
    mockCtx.bots = [bot("m", "Main", { primary: true })];
    await render(<Sidebar {...props} />);
    expect(screen.getByRole("heading", { name: "Just Main so far" })).toBeOnTheScreen();
  });

  it("clears a search that matches nothing", async () => {
    const props = setup(MEMBER);
    Object.assign(mockCtx, { bots: [bot("a", "Ada")], filter: "zz" });
    await render(<Sidebar {...props} />);
    expect(screen.getByText("No Bots match “zz”.")).toBeOnTheScreen();
    await act(async () => fireEvent.press(screen.getByRole("button", { name: "Clear search" })));
    expect(mockCtx.setFilter).toHaveBeenCalledWith("");
  });

  it("explains an empty hidden list", async () => {
    const props = setup(MEMBER);
    Object.assign(mockCtx, { bots: [bot("a", "Ada")], showHidden: true });
    await render(<Sidebar {...props} />);
    expect(screen.getByRole("heading", { name: "No hidden Bots" })).toBeOnTheScreen();
  });
});
