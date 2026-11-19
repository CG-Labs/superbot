import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";
import { defaultServerUrl, LOCAL_SERVER_URL, loadSavedCredentials, saveCredentials } from "../auth";

jest.mock("expo-secure-store", () => ({
  setItemAsync: jest.fn(),
  getItemAsync: jest.fn(async () => null),
  deleteItemAsync: jest.fn(),
}));

const BASE = "https://bots.example.com";
const store = new Map<string, string>();
const fakeStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
};

describe("saved credentials", () => {
  const os = Platform.OS;
  beforeEach(() => {
    store.clear();
    jest.clearAllMocks();
    (globalThis as { localStorage?: unknown }).localStorage = fakeStorage;
  });
  afterEach(() => {
    Platform.OS = os;
  });

  it("keeps a session token and drops any old password", async () => {
    Platform.OS = "web";
    store.set("superbot.password", "old");
    await saveCredentials({ baseUrl: BASE, token: "sbs_t" });
    expect(store.get("superbot.token")).toBe("sbs_t");
    expect(store.has("superbot.password")).toBe(false);
    expect(await loadSavedCredentials()).toEqual({ baseUrl: BASE, token: "sbs_t" });
  });

  it("never writes a password to browser storage", async () => {
    Platform.OS = "web";
    const password = crypto.randomUUID();
    await saveCredentials({ baseUrl: BASE, password });
    expect([...store.values()]).not.toContain(password);
    expect(await loadSavedCredentials()).toBeNull();
  });

  it("keeps a legacy password in the phone's keychain", async () => {
    Platform.OS = "ios";
    const password = crypto.randomUUID();
    await saveCredentials({ baseUrl: BASE, password });
    expect(SecureStore.setItemAsync).toHaveBeenCalledWith("superbot.password", password);
  });
});

describe("default server URL", () => {
  const served = { protocol: "https:", origin: BASE };

  it("is the page's origin for a web build the server hosts", () => {
    expect(defaultServerUrl("web", served, false)).toBe(BASE);
    expect(defaultServerUrl("web", { protocol: "http:", origin: "http://localhost" }, false)).toBe("http://localhost");
  });

  it("stays local for the dev server, Electron, and native", () => {
    expect(defaultServerUrl("web", served, true)).toBe(LOCAL_SERVER_URL);
    expect(defaultServerUrl("web", { protocol: "file:", origin: "null" }, false)).toBe(LOCAL_SERVER_URL);
    expect(defaultServerUrl("web", undefined, false)).toBe(LOCAL_SERVER_URL);
    expect(defaultServerUrl("ios", served, false)).toBe(LOCAL_SERVER_URL);
  });
});
