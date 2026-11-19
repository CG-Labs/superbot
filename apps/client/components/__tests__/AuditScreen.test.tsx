import React from "react";
import { render, screen } from "@testing-library/react-native";
import AuditScreen from "../../app/audit";

jest.mock("expo-router", () => ({ Redirect: () => null, router: { canGoBack: () => false, back: jest.fn(), replace: jest.fn() } }));
jest.mock("../AuditLog", () => {
  const { Text } = jest.requireActual("react-native");
  return { AuditLog: () => <Text>Audit log component</Text> };
});
const mockCtx: Record<string, unknown> = {};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));

describe("audit route", () => {
  it("shows the log to admins", async () => {
    Object.assign(mockCtx, { api: {}, bots: [], me: { name: "Owner", role: "admin", permissions: ["account", "read", "admin"] } });
    await render(<AuditScreen />);
    expect(screen.getByText("Audit log component")).toBeOnTheScreen();
  });

  it("tells anyone else it's for admins, without loading it", async () => {
    Object.assign(mockCtx, { api: {}, bots: [], me: { name: "Alex", role: "member", permissions: ["account", "read", "write"] } });
    await render(<AuditScreen />);
    expect(screen.getByText("Only admins can see the audit log.")).toBeOnTheScreen();
    expect(screen.queryByText("Audit log component")).toBeNull();
  });
});
