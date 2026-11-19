import * as WebBrowser from "expo-web-browser";
import {
  fetchSsoProviders,
  newPkce,
  parseSsoReturn,
  redeemSso,
  signInWithSso,
  ssoButtonText,
  ssoButtonTone,
  ssoProviderList,
  ssoRedirect,
  ssoStartUrl,
  SSO_ERRORS,
} from "../sso";

type NodeCrypto = {
  createHash(alg: string): { update(data: string): { digest(enc: string): string } };
  randomBytes(n: number): Uint8Array;
};
const sha256 = (data: string, enc = "base64url") => jest.requireActual<NodeCrypto>("crypto").createHash("sha256").update(data).digest(enc);

jest.mock("expo-crypto", () => {
  const c = jest.requireActual<NodeCrypto>("crypto");
  return {
    CryptoDigestAlgorithm: { SHA256: "SHA-256" },
    CryptoEncoding: { BASE64: "base64" },
    getRandomBytes: (n: number) => new Uint8Array(c.randomBytes(n)),
    digestStringAsync: async (_alg: string, data: string) => c.createHash("sha256").update(data).digest("base64"),
  };
});
// Absolute paths resolve against the page origin, as expo-linking does on the web.
jest.mock("expo-linking", () => ({
  createURL: (path: string) => (path.startsWith("/") ? `https://bots.example.com${path}` : `superbot://${path}`),
}));
jest.mock("expo-web-browser", () => ({ openAuthSessionAsync: jest.fn(), maybeCompleteAuthSession: jest.fn() }));

const BASE = "https://bots.example.com/";
const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  jest.clearAllMocks();
});

function respond(status: number, body: unknown) {
  return jest.fn(async () => ({ ok: status < 300, status, json: async () => body })) as unknown as typeof fetch;
}

describe("PKCE", () => {
  it("makes an S256 challenge of a fresh, URL-safe verifier", async () => {
    const a = await newPkce();
    const b = await newPkce();
    expect(a.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).toBe(sha256(a.verifier));
  });
});

describe("the start URL", () => {
  it("asks for a token session and carries the redirect, challenge, and state", () => {
    const url = new URL(ssoStartUrl(BASE, "entra", { redirect: "superbot://auth", challenge: "c".repeat(43), state: "s1", label: "Phone" }));
    expect(url.origin + url.pathname).toBe("https://bots.example.com/api/auth/sso/entra/start");
    expect(Object.fromEntries(url.searchParams)).toEqual({ session: "token", redirect: "superbot://auth", challenge: "c".repeat(43), state: "s1", label: "Phone" });
  });
});

describe("the redirect back to the app", () => {
  it("comes back to the web build's base path, or the app scheme", () => {
    expect(ssoRedirect("web", "/app")).toBe("https://bots.example.com/app/auth");
    expect(ssoRedirect("ios", "/app")).toBe("superbot://auth");
    expect(ssoRedirect("android", undefined)).toBe("superbot://auth");
  });

  it("gives the code only when the state is ours", () => {
    expect(parseSsoReturn("superbot://auth?code=sbh_1&state=s1", "s1")).toEqual({ code: "sbh_1" });
    expect(parseSsoReturn("superbot://auth?code=sbh_1&state=other", "s1")).toEqual({ error: SSO_ERRORS.sso_expired });
    expect(parseSsoReturn("superbot://auth", "s1")).toEqual({ error: SSO_ERRORS.sso_expired });
  });

  it("explains the server's error codes, and nothing else it sends", () => {
    expect(parseSsoReturn("superbot://auth?error=sso_not_linked&state=s1", "s1")).toEqual({ error: SSO_ERRORS.sso_not_linked });
    expect(parseSsoReturn("superbot://auth?error=%3Cscript%3E&state=s1", "s1")).toEqual({ error: SSO_ERRORS.sso_failed });
  });
});

describe("the provider list", () => {
  it("keeps every provider the server offers, in its order", () => {
    const three = [
      { id: "entra", label: "Microsoft", type: "entra" },
      { id: "google", label: "Google", type: "google" },
      { id: "okta", label: "Okta", type: "oidc" },
    ];
    expect(ssoProviderList(three)).toEqual(three);
  });

  it("drops entries that can't be a provider, and repeats", () => {
    expect(
      ssoProviderList([
        { id: "google", label: "Google", type: "google" },
        { id: "google", label: "Google again", type: "google" },
        { id: "../admin", label: "Sneaky", type: "oidc" },
        { id: "Okta", label: "Okta", type: "oidc" },
        { id: 7, label: "Number" },
        null,
        "entra",
        { id: "acme", label: "  ", type: 3 },
        { id: "long", label: "x".repeat(60), type: "oidc" },
      ]),
    ).toEqual([
      { id: "google", label: "Google", type: "google" },
      { id: "acme", label: "acme", type: "oidc" },
      { id: "long", label: "x".repeat(40), type: "oidc" },
    ]);
    expect(ssoProviderList(undefined)).toEqual([]);
    expect(ssoProviderList({ id: "entra" })).toEqual([]);
  });

  it("explains a refused account", () => {
    expect(parseSsoReturn("superbot://auth?error=sso_wrong_account&state=s1", "s1")).toEqual({ error: SSO_ERRORS.sso_wrong_account });
  });

  it("keeps GitHub, Apple, and SAML beside the OIDC providers", () => {
    const six = [
      { id: "entra", label: "Microsoft", type: "entra" },
      { id: "google", label: "Google", type: "google" },
      { id: "github", label: "GitHub", type: "github" },
      { id: "apple", label: "Apple", type: "apple" },
      { id: "okta", label: "Okta", type: "oidc" },
      { id: "adfs", label: "Company SSO", type: "saml" },
    ];
    expect(ssoProviderList(six)).toEqual(six);
  });
});

describe("the buttons", () => {
  it("say Sign in with Apple exactly, in Apple's style, whatever the label", () => {
    expect(ssoButtonText({ id: "apple", label: "Apple", type: "apple" })).toBe("Sign in with Apple");
    expect(ssoButtonText({ id: "work", label: "Work Apple ID", type: "apple" })).toBe("Sign in with Apple");
    expect(ssoButtonTone({ id: "work", label: "Work Apple ID", type: "apple" })).toBe("apple");
  });

  it("use the server's label for the others", () => {
    expect(ssoButtonText({ id: "github", label: "GitHub Enterprise", type: "github" })).toBe("Sign in with GitHub Enterprise");
    expect(ssoButtonText({ id: "entra", label: "Microsoft", type: "entra" })).toBe("Sign in with Microsoft");
    expect(ssoButtonTone({ id: "github", label: "GitHub", type: "github" })).toBe("plain");
  });

  it("show a SAML IdP behind the bridge like any other", () => {
    expect(ssoButtonText({ id: "adfs", label: "Company SSO", type: "saml" })).toBe("Sign in with Company SSO");
    expect(ssoButtonTone({ id: "adfs", label: "Acme", type: "saml" })).toBe("plain");
  });
});

describe("talking to the server", () => {
  it("lists several providers from one server", async () => {
    const providers = [
      { id: "entra", label: "Microsoft", type: "entra" },
      { id: "google", label: "Google", type: "google" },
      { id: "keycloak", label: "Acme SSO", type: "oidc" },
    ];
    globalThis.fetch = respond(200, { providers: [...providers, { id: "bad id" }] });
    expect(await fetchSsoProviders(BASE)).toEqual(providers);
    globalThis.fetch = respond(200, { providers: "nope" });
    expect(await fetchSsoProviders(BASE)).toEqual([]);
  });

  it("lists providers, and none from a server without SSO", async () => {
    globalThis.fetch = respond(200, { providers: [{ id: "entra", label: "Microsoft", type: "entra" }] });
    expect(await fetchSsoProviders(BASE)).toEqual([{ id: "entra", label: "Microsoft", type: "entra" }]);
    expect(globalThis.fetch).toHaveBeenCalledWith("https://bots.example.com/api/auth/sso");
    globalThis.fetch = respond(401, {});
    expect(await fetchSsoProviders(BASE)).toEqual([]);
    globalThis.fetch = jest.fn(async () => Promise.reject(new Error("offline"))) as unknown as typeof fetch;
    expect(await fetchSsoProviders(BASE)).toEqual([]);
  });

  it("redeems the code with the verifier for a session token", async () => {
    globalThis.fetch = respond(200, { token: "sbs_t" });
    expect(await redeemSso(BASE, "sbh_1", "v", "Phone")).toEqual({ baseUrl: BASE, token: "sbs_t" });
    const [, init] = (globalThis.fetch as jest.Mock).mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ sso: "sbh_1", verifier: "v", session: "token", label: "Phone" });
    globalThis.fetch = respond(401, { error: "That sign-in expired or was already used. Try again." });
    await expect(redeemSso(BASE, "sbh_1", "v", "Phone")).rejects.toThrow("already used");
  });
});

describe("signInWithSso", () => {
  const open = WebBrowser.openAuthSessionAsync as jest.Mock;

  it("opens the system browser and redeems what comes back", async () => {
    open.mockImplementation(async (url: string, redirect: string) => {
      const q = new URL(url).searchParams;
      expect(redirect).toBe("superbot://auth");
      expect(q.get("redirect")).toBe("superbot://auth");
      return { type: "success", url: `superbot://auth?code=sbh_9&state=${q.get("state")}` };
    });
    globalThis.fetch = respond(200, { token: "sbs_t" });
    expect(await signInWithSso(BASE, "entra")).toEqual({ baseUrl: BASE, token: "sbs_t" });
    const [, init] = (globalThis.fetch as jest.Mock).mock.calls[0];
    const sent = JSON.parse(init.body);
    const challenge = new URL(open.mock.calls[0][0]).searchParams.get("challenge");
    expect(sha256(sent.verifier)).toBe(challenge);
  });

  it("signs in with GitHub, Apple, and a SAML bridge the same way, the server doing the IdP's part", async () => {
    for (const id of ["github", "apple", "adfs"]) {
      open.mockImplementation(async (url: string) => {
        const u = new URL(url);
        expect(u.pathname).toBe(`/api/auth/sso/${id}/start`);
        return { type: "success", url: `superbot://auth?code=sbh_${id}&state=${u.searchParams.get("state")}` };
      });
      globalThis.fetch = respond(200, { token: `sbs_${id}` });
      expect(await signInWithSso(BASE, id)).toEqual({ baseUrl: BASE, token: `sbs_${id}` });
      expect(JSON.parse((globalThis.fetch as jest.Mock).mock.calls[0][1].body).sso).toBe(`sbh_${id}`);
    }
  });

  it("shows why GitHub or Apple refused, from the server's code only", async () => {
    open.mockImplementation(async (url: string) => ({ type: "success", url: `superbot://auth?error=sso_wrong_account&state=${new URL(url).searchParams.get("state")}` }));
    globalThis.fetch = jest.fn() as unknown as typeof fetch;
    await expect(signInWithSso(BASE, "github")).rejects.toThrow(SSO_ERRORS.sso_wrong_account);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("opens the popup in the same tick as the click once providers are loaded", async () => {
    globalThis.fetch = respond(200, { providers: [{ id: "entra", label: "Microsoft", type: "entra" }] });
    await fetchSsoProviders(BASE);
    await new Promise((r) => setTimeout(r, 0));
    open.mockClear();
    open.mockResolvedValue({ type: "cancel" });
    const signingIn = signInWithSso(BASE, "entra");
    expect(open).toHaveBeenCalledTimes(1);
    await expect(signingIn).rejects.toThrow(SSO_ERRORS.sso_cancelled);
  });

  it("stops when the person closes the browser", async () => {
    open.mockResolvedValue({ type: "cancel" });
    globalThis.fetch = jest.fn() as unknown as typeof fetch;
    await expect(signInWithSso(BASE, "entra")).rejects.toThrow(SSO_ERRORS.sso_cancelled);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
