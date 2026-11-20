import { Linking } from "react-native";
import { ApiError } from "../api";
import { consoleUrl, isAdmin, openConsole, openSetup, setupPending, setupUrl } from "../admin";
import type { Me, SetupStatus } from "../types";

const ADMIN: Me = { name: "Owner", role: "admin", permissions: ["account", "read", "admin"] };
const status = (show: boolean): SetupStatus => ({
  progress: { step: "domain", show, dismissed: !show, completedAt: null },
  checklist: [],
  done: 2,
  total: 5,
});

describe("admin console link (ADR 0027)", () => {
  it("is for admins only, by the permissions the server grants", () => {
    expect(isAdmin({ name: "Owner", role: "admin", permissions: ["account", "read", "admin"] })).toBe(true);
    expect(isAdmin({ name: "Alex", role: "member", permissions: ["account", "read", "write"] })).toBe(false);
    expect(isAdmin({ name: "Scout", role: "bot", permissions: ["account", "read", "write"] })).toBe(false);
    expect(isAdmin({ name: "You" })).toBe(false);
  });

  it("points at /console/ on the server this client talks to", () => {
    expect(consoleUrl("https://bots.example.com")).toBe("https://bots.example.com/console/");
    expect(consoleUrl("https://bots.example.com/")).toBe("https://bots.example.com/console/");
    expect(consoleUrl(" 127.0.0.1:3000 ")).toBe("http://127.0.0.1:3000/console/");
  });

  it("opens it in the browser", async () => {
    const open = jest.spyOn(Linking, "openURL").mockResolvedValue(undefined);
    await openConsole("https://bots.example.com");
    expect(open).toHaveBeenCalledWith("https://bots.example.com/console/");
    open.mockRestore();
  });
});

describe("setup wizard link (ADR 0034)", () => {
  it("opens the console's Setup tab", async () => {
    expect(setupUrl("https://bots.example.com/")).toBe("https://bots.example.com/console/#setup");
    const open = jest.spyOn(Linking, "openURL").mockResolvedValue(undefined);
    await openSetup("https://bots.example.com");
    expect(open).toHaveBeenCalledWith("https://bots.example.com/console/#setup");
    open.mockRestore();
  });

  it("is pending for admins until the wizard is finished or hidden", async () => {
    expect(await setupPending({ setupStatus: async () => status(true) }, ADMIN)).toBe(true);
    expect(await setupPending({ setupStatus: async () => status(false) }, ADMIN)).toBe(false);
  });

  it("never asks the server for anyone but admins", async () => {
    const setupStatus = jest.fn(async () => status(true));
    expect(await setupPending({ setupStatus }, { name: "Alex", role: "member", permissions: ["account", "read", "write"] })).toBe(false);
    expect(await setupPending({ setupStatus }, { name: "You" })).toBe(false);
    expect(setupStatus).not.toHaveBeenCalled();
  });

  it("stays quiet on servers without the wizard", async () => {
    const missing = async (): Promise<SetupStatus> => {
      throw new ApiError("Not found", 404);
    };
    expect(await setupPending({ setupStatus: missing }, ADMIN)).toBe(false);
  });
});
