import React from "react";
import { render, screen } from "@testing-library/react-native";
import AuditScreen from "../../app/audit";

jest.mock("expo-router", () => ({
  Redirect: ({ href }: { href: string }) => mockRedirect(href),
  router: { canGoBack: () => false, back: jest.fn(), replace: jest.fn() },
  useLocalSearchParams: () => mockParams,
}));
jest.mock("../AuditLog", () => {
  const { Text } = jest.requireActual("react-native");
  return { AuditLog: (p: { initial?: object; bots?: unknown[] }) => <Text>Audit log component {JSON.stringify({ initial: p.initial, bots: p.bots?.length })}</Text> };
});
const mockCtx: Record<string, unknown> = {};
let mockParams: Record<string, string> = {};
const mockRedirect = jest.fn((_href: string) => null);
beforeEach(() => {
  mockRedirect.mockClear();
  mockParams = {};
});
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

describe("audit route", () => {
  it("shows the log to admins", async () => {
    Object.assign(mockCtx, { ready: true, api: {}, bots: [], me: { name: "Owner", role: "admin", permissions: ["account", "read", "admin"] } });
    await render(<AuditScreen />);
    expect(screen.getByText(/^Audit log component/)).toBeOnTheScreen();
  });

  it("opens filtered from a link, with the Bots to filter by", async () => {
    mockParams = { bot: "b1", session: " s1 ", tab: "x" };
    Object.assign(mockCtx, { ready: true, api: {}, bots: [{ id: "b1", name: "Scout" }], me: { name: "Owner", role: "admin", permissions: ["admin"] } });
    await render(<AuditScreen />);
    expect(screen.getByText('Audit log component {"initial":{"bot":"b1","session":"s1"},"bots":1}')).toBeOnTheScreen();
  });

  it("tells anyone else it's for admins, without loading it", async () => {
    Object.assign(mockCtx, { ready: true, api: {}, bots: [], me: { name: "Alex", role: "member", permissions: ["account", "read", "write"] } });
    await render(<AuditScreen />);
    expect(screen.getByText("Only admins can see the audit log.")).toBeOnTheScreen();
    expect(screen.queryByText(/^Audit log component/)).toBeNull();
  });

  it("waits for the saved session on a reload instead of sending people home", async () => {
    Object.assign(mockCtx, { ready: false, api: null, bots: [], me: { name: "" } });
    await render(<AuditScreen />);
    expect(mockRedirect).not.toHaveBeenCalled();
    Object.assign(mockCtx, { ready: true });
    await render(<AuditScreen />);
    expect(mockRedirect).toHaveBeenCalledWith("/");
  });
});
