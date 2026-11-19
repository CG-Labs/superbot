import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { LoginScreen } from "../LoginScreen";
import { LOCAL_SERVER_URL } from "../../src/auth";

type NodeCrypto = {
  createHash(alg: string): { update(data: string): { digest(enc: string): string } };
  randomBytes(n: number): Uint8Array;
};

const mockCtx: Record<string, unknown> = {};
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));
jest.mock("expo-crypto", () => {
  const c = jest.requireActual<NodeCrypto>("crypto");
  return {
    CryptoDigestAlgorithm: { SHA256: "SHA-256" },
    CryptoEncoding: { BASE64: "base64" },
    getRandomBytes: (n: number) => new Uint8Array(c.randomBytes(n)),
    digestStringAsync: async (_alg: string, data: string) => c.createHash("sha256").update(data).digest("base64"),
  };
});
jest.mock("expo-web-browser", () => ({ openAuthSessionAsync: jest.fn(), maybeCompleteAuthSession: jest.fn() }));

const realFetch = globalThis.fetch;
function serverWith(providers: unknown) {
  globalThis.fetch = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ providers }) })) as unknown as typeof fetch;
}

beforeEach(() => {
  Object.assign(mockCtx, { login: jest.fn(), loginWithSso: jest.fn(async () => {}), error: null });
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("LoginScreen", () => {
  it("shows one button per provider the server offers, in its order", async () => {
    serverWith([
      { id: "entra", label: "Microsoft", type: "entra" },
      { id: "google", label: "Google", type: "google" },
      { id: "okta", label: "Okta", type: "oidc" },
    ]);
    const user = userEvent.setup();
    await render(<LoginScreen />);

    await screen.findByText("Sign in with Okta", {}, { timeout: 2000 });
    const labels = screen.getAllByText(/^Sign in with /).map((n) => n.props.children.join(""));
    expect(labels).toEqual(["Sign in with Microsoft", "Sign in with Google", "Sign in with Okta"]);
    expect(globalThis.fetch).toHaveBeenCalledWith(`${LOCAL_SERVER_URL}/api/auth/sso`);

    await user.press(screen.getByText("Sign in with Google"));
    expect(mockCtx.loginWithSso).toHaveBeenCalledWith(LOCAL_SERVER_URL, "google");
  });

  it("shows no SSO buttons when the server has none", async () => {
    serverWith([]);
    await render(<LoginScreen />);
    await new Promise((r) => setTimeout(r, 600));
    expect(screen.queryByText(/^Sign in with /)).not.toBeOnTheScreen();
    expect(screen.getByText("Connect")).toBeOnTheScreen();
  });
});
