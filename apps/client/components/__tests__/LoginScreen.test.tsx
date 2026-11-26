import React from "react";
import { render, screen, userEvent } from "@testing-library/react-native";
import { LoginScreen, signInErrorMessage } from "../LoginScreen";
import { LOCAL_SERVER_URL } from "../../src/auth";
import { ApiError, MfaRequired } from "../../src/api";
import { themes } from "../../src/theme";

type NodeCrypto = {
  createHash(alg: string): { update(data: string): { digest(enc: string): string } };
  randomBytes(n: number): Uint8Array;
};

const mockCtx: Record<string, unknown> = {};
let mockScheme: "light" | "dark" | null = null;
jest.mock("react-native/Libraries/Utilities/useColorScheme", () => ({ __esModule: true, default: () => mockScheme }));
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
  Object.assign(mockCtx, { login: jest.fn(), loginSecondFactor: jest.fn(), loginWithSso: jest.fn(async () => {}), error: null });
});
afterEach(() => {
  globalThis.fetch = realFetch;
  mockScheme = null;
});

describe("signInErrorMessage", () => {
  const url = "https://bots.example";
  it.each([
    [new TypeError("Failed to fetch"), `Can't reach a SuperBot server at ${url}. Check the server URL and your connection.`],
    [new TypeError("Network request failed"), `Can't reach a SuperBot server at ${url}. Check the server URL and your connection.`],
    [new TypeError("Load failed"), `Can't reach a SuperBot server at ${url}. Check the server URL and your connection.`],
    [new ApiError("HTTP 502", 502), `The server at ${url} had a problem (HTTP 502). Try again in a moment.`],
    [new ApiError("Wrong password.", 401), "Wrong password."],
    [new ApiError("Too many failed sign-ins. Try again later.", 429), "Too many failed sign-ins. Try again later."],
    [new Error("A sign-in code or password is required"), "A sign-in code or password is required"],
    ["odd", "Sign-in failed. Try again."],
  ])("explains %p", (err, message) => {
    expect(signInErrorMessage(err, url)).toBe(message);
  });
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
    const labels = screen.getAllByText(/^Sign in with /).map((n) => n.props.children);
    expect(labels).toEqual(["Sign in with Microsoft", "Sign in with Google", "Sign in with Okta"]);
    expect(globalThis.fetch).toHaveBeenCalledWith(`${LOCAL_SERVER_URL}/api/auth/sso`);

    await user.press(screen.getByText("Sign in with Google"));
    expect(mockCtx.loginWithSso).toHaveBeenCalledWith(LOCAL_SERVER_URL, "google");
  });

  it("shows GitHub and Apple, with Apple's button in Apple's wording", async () => {
    serverWith([
      { id: "github", label: "GitHub", type: "github" },
      { id: "apple", label: "Work Apple ID", type: "apple" },
    ]);
    const user = userEvent.setup();
    await render(<LoginScreen />);

    const apple = await screen.findByText("Sign in with Apple", {}, { timeout: 2000 });
    expect(screen.getAllByText(/^Sign in with /).map((n) => n.props.children)).toEqual(["Sign in with GitHub", "Sign in with Apple"]);

    await user.press(apple);
    expect(mockCtx.loginWithSso).toHaveBeenCalledWith(LOCAL_SERVER_URL, "apple");
    await user.press(screen.getByText("Sign in with GitHub"));
    expect(mockCtx.loginWithSso).toHaveBeenCalledWith(LOCAL_SERVER_URL, "github");
  });

  it.each([
    ["light", "#000000", "#ffffff"],
    ["dark", "#ffffff", "#000000"],
  ] as const)("in %s mode, keeps Apple's button black or white and the others on the theme", async (scheme, bg, text) => {
    mockScheme = scheme;
    serverWith([
      { id: "github", label: "GitHub", type: "github" },
      { id: "apple", label: "Apple", type: "apple" },
    ]);
    await render(<LoginScreen />);

    const apple = await screen.findByText("Sign in with Apple", {}, { timeout: 2000 });
    expect(apple).toHaveStyle({ color: text });
    expect(screen.getByRole("button", { name: "Sign in with Apple" })).toHaveStyle({ backgroundColor: bg });
    expect(screen.getByText("Sign in with GitHub")).toHaveStyle({ color: themes[scheme].c.text });
    expect(screen.getByRole("button", { name: "Sign in with GitHub" })).toHaveStyle({ backgroundColor: themes[scheme].c.raised });
    expect(screen.getByRole("button", { name: "Connect" })).toHaveStyle({ backgroundColor: themes[scheme].c.accent });
  });

  it("says plainly when the server can't be reached, in an alert", async () => {
    serverWith([]);
    mockCtx.login = jest.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    const user = userEvent.setup();
    await render(<LoginScreen inviteCode={"sbc_" + "e".repeat(64)} />);
    await user.press(screen.getByText("Connect"));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(`Can't reach a SuperBot server at ${LOCAL_SERVER_URL}. Check the server URL and your connection.`);
  });

  it("shows the server's own message when it turns the code down", async () => {
    serverWith([]);
    mockCtx.login = jest.fn(async () => {
      throw new ApiError("That sign-in code has expired. Ask an admin for a new one.", 401);
    });
    const user = userEvent.setup();
    await render(<LoginScreen inviteCode={"sbc_" + "f".repeat(64)} />);
    await user.press(screen.getByText("Connect"));
    expect(await screen.findByRole("alert")).toHaveTextContent("That sign-in code has expired. Ask an admin for a new one.");
  });

  it("shows why the last session ended", async () => {
    serverWith([]);
    mockCtx.error = "Your session ended. Sign in again.";
    await render(<LoginScreen />);
    expect(screen.getByRole("alert")).toHaveTextContent("Your session ended. Sign in again.");
  });

  it("fills in the code from an invite link, and signs in only when asked", async () => {
    serverWith([]);
    const code = "sbc_" + "cd".repeat(32);
    const user = userEvent.setup();
    await render(<LoginScreen inviteCode={code} />);
    expect(screen.getByText(/invite code is filled in/)).toBeOnTheScreen();
    expect(mockCtx.login).not.toHaveBeenCalled();
    await user.press(screen.getByText("Connect"));
    expect(mockCtx.login).toHaveBeenCalledWith(LOCAL_SERVER_URL, code);
  });

  it("shows no SSO buttons when the server has none", async () => {
    serverWith([]);
    await render(<LoginScreen />);
    await new Promise((r) => setTimeout(r, 600));
    expect(screen.queryByText(/^Sign in with /)).not.toBeOnTheScreen();
    expect(screen.getByText("Connect")).toBeOnTheScreen();
  });

  it("asks for the second factor, and accepts a recovery code", async () => {
    serverWith([]);
    const finish = jest.fn(async () => {});
    mockCtx.login = jest.fn(async () => {
      throw new MfaRequired("Enter the code from your authenticator app, or a recovery code.", "sbm_1", "totp", null);
    });
    mockCtx.loginSecondFactor = jest
      .fn()
      .mockRejectedValueOnce(new MfaRequired("That code is wrong. Try again.", "sbm_1", "totp", null))
      .mockResolvedValueOnce({ recoveryCodes: null, finish });
    const user = userEvent.setup();
    await render(<LoginScreen inviteCode={"sbc_" + "a".repeat(64)} />);
    await user.press(screen.getByText("Connect"));
    expect(await screen.findByText("Verify")).toBeOnTheScreen();
    expect(screen.queryByTestId("mfa-setup")).not.toBeOnTheScreen();

    await user.type(screen.getByLabelText("Second factor"), "000 000");
    await user.press(screen.getByText("Verify"));
    expect(mockCtx.loginSecondFactor).toHaveBeenLastCalledWith(LOCAL_SERVER_URL, "sbm_1", { totp: "000000" });
    expect(await screen.findByText("That code is wrong. Try again.")).toBeOnTheScreen();

    await user.type(screen.getByLabelText("Second factor"), "abcde-fghij");
    await user.press(screen.getByText("Verify"));
    expect(mockCtx.loginSecondFactor).toHaveBeenLastCalledWith(LOCAL_SERVER_URL, "sbm_1", { recoveryCode: "abcde-fghij" });
    expect(finish).toHaveBeenCalled();
  });

  it("sets up an authenticator app at sign-in, then shows the recovery codes before going on", async () => {
    serverWith([]);
    const finish = jest.fn(async () => {});
    const setup = { secret: "JBSWY3DPEHPK3PXP", otpauthUrl: "otpauth://totp/SuperBot:a?secret=JBSWY3DPEHPK3PXP", qrSvg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>' };
    mockCtx.login = jest.fn(async () => {
      throw new MfaRequired("This server requires two-factor authentication for your account.", "sbm_2", "enroll", setup);
    });
    mockCtx.loginSecondFactor = jest.fn(async () => ({ recoveryCodes: ["aaaaa-bbbbb", "ccccc-ddddd"], finish }));
    const user = userEvent.setup();
    await render(<LoginScreen inviteCode={"sbc_" + "b".repeat(64)} />);
    await user.press(screen.getByText("Connect"));
    expect(await screen.findByTestId("mfa-setup")).toBeOnTheScreen();
    expect(screen.getByTestId("mfa-key")).toHaveTextContent("JBSW Y3DP EHPK 3PXP");

    await user.type(screen.getByLabelText("Second factor"), "123456");
    await user.press(screen.getByText("Turn on and connect"));
    expect(mockCtx.loginSecondFactor).toHaveBeenCalledWith(LOCAL_SERVER_URL, "sbm_2", { totp: "123456" });
    expect(await screen.findByText("ccccc-ddddd")).toBeOnTheScreen();
    expect(finish).not.toHaveBeenCalled();
    await user.press(screen.getByText("I saved them. Continue"));
    expect(finish).toHaveBeenCalled();
  });
});
