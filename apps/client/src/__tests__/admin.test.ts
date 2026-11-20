import { Linking } from "react-native";
import { consoleUrl, isAdmin, openConsole } from "../admin";

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
