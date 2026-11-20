import { encode as b64encode } from "base-64";
import * as Crypto from "expo-crypto";
import * as Linking from "expo-linking";
import * as WebBrowser from "expo-web-browser";
import { Platform } from "react-native";
import { ApiError } from "./api";
import { normalizeBaseUrl } from "./auth";
import type { ServerConfig } from "./types";

/** A single sign-on provider the server offers (ADR 0014). */
export interface SsoProvider {
  id: string;
  label: string;
  type: string;
}

/** Messages for the fixed error codes the server sends back. */
export const SSO_ERRORS: Record<string, string> = {
  sso_not_linked: "Your account isn't set up on this server yet. Ask an admin to add you.",
  sso_not_allowed: "Your SuperBot account is disabled.",
  sso_wrong_account: "That account can't sign in here. Use your organization's account, with a verified email.",
  sso_email_taken: "A user with your email already exists. Ask an admin to link your sign-in to it.",
  sso_no_seat: "This server has no seats left for new people. Ask an admin to free one or add seats.",
  sso_cancelled: "Sign-in was cancelled.",
  sso_expired: "That sign-in expired. Try again.",
  sso_too_many: "Too many failed sign-ins. Try again later.",
  sso_unavailable: "That sign-in option isn't available.",
  sso_failed: "Single sign-on failed. Try again, or ask an admin to check the audit log.",
};

/**
 * The desktop app loads from file://, which no IdP can send people back to; it signs
 * in with a code or password instead.
 */
export function ssoSupported(): boolean {
  return Platform.OS !== "web" || (typeof location !== "undefined" && location.protocol.startsWith("http"));
}

/**
 * One button per provider, in the server's order (Entra, Google, GitHub, Apple, any OIDC
 * IdP, and SAML IdPs through a bridge can be on at once; the server lists only those it has secrets for). Entries that aren't a provider the server could have, or repeat one, are
 * dropped, so a bad response can't make a button that goes somewhere odd.
 */
export function ssoProviderList(raw: unknown): SsoProvider[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const list: SsoProvider[] = [];
  for (const p of raw as Partial<Record<keyof SsoProvider, unknown>>[]) {
    const { id, label, type } = p ?? {};
    if (typeof id !== "string" || !/^[a-z0-9]{1,32}$/.test(id) || seen.has(id)) continue;
    const name = typeof label === "string" && label.trim() ? label.trim().slice(0, 40) : id;
    seen.add(id);
    list.push({ id, label: name, type: typeof type === "string" ? type : "oidc" });
  }
  return list;
}

/**
 * The button's text. Apple's guidelines want exactly "Sign in with Apple", so a custom
 * label doesn't change it; the others use the label the server sends.
 */
export function ssoButtonText(p: SsoProvider): string {
  return p.type === "apple" ? "Sign in with Apple" : `Sign in with ${p.label}`;
}

/** Apple's button is white on a dark screen (its guidelines); the rest share one style. */
export function ssoButtonTone(p: SsoProvider): "apple" | "plain" {
  return p.type === "apple" ? "apple" : "plain";
}

/** The providers on this server; none when it's older or unreachable. */
export async function fetchSsoProviders(baseUrl: string): Promise<SsoProvider[]> {
  try {
    const res = await fetch(`${normalizeBaseUrl(baseUrl)}/api/auth/sso`);
    if (!res.ok) return [];
    const data = (await res.json()) as { providers?: unknown };
    const list = ssoProviderList(data?.providers);
    if (list.length) prepareSso();
    return list;
  } catch {
    return [];
  }
}

export function base64Url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(): string {
  const bytes = Crypto.getRandomBytes(32);
  return base64Url(b64encode(String.fromCharCode(...bytes)));
}

/** RFC 7636: a random verifier, and its SHA-256 as the S256 challenge. */
export async function newPkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomString();
  const digest = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, verifier, {
    encoding: Crypto.CryptoEncoding.BASE64,
  });
  return { verifier, challenge: base64Url(digest) };
}

// Browsers only allow a popup straight from a click, so the digest is done before it.
let prepared: { verifier: string; challenge: string } | null = null;

/** Makes the PKCE pair for the next sign-in ahead of time. */
export function prepareSso(): void {
  if (!prepared) void newPkce().then((p) => (prepared = prepared ?? p));
}

/**
 * Where the server sends the one-time code: `superbot://auth` in the native app, the
 * `auth` route on the web, under the build's base path (`/app/auth` when botd's
 * installer or Compose serves it).
 */
export function ssoRedirect(os: string = Platform.OS, base: string | undefined = process.env.EXPO_BASE_URL): string {
  return Linking.createURL(os === "web" && base ? `${base}/auth` : "auth");
}

export function ssoStartUrl(
  baseUrl: string,
  providerId: string,
  p: { redirect: string; challenge: string; state: string; label: string },
): string {
  const q = new URLSearchParams({ session: "token", redirect: p.redirect, challenge: p.challenge, state: p.state, label: p.label });
  return `${normalizeBaseUrl(baseUrl)}/api/auth/sso/${encodeURIComponent(providerId)}/start?${q}`;
}

/** The one-time code from the server's redirect back to the app, or why there isn't one. */
export function parseSsoReturn(url: string, state: string): { code: string } | { error: string } {
  const query = url.includes("?") ? url.slice(url.indexOf("?") + 1).split("#")[0] : "";
  const q = new URLSearchParams(query);
  if (q.get("state") !== state) return { error: SSO_ERRORS.sso_expired };
  const error = q.get("error");
  if (error) return { error: SSO_ERRORS[error] ?? SSO_ERRORS.sso_failed };
  const code = q.get("code");
  return code ? { code } : { error: SSO_ERRORS.sso_failed };
}

/** Trades the one-time code and the PKCE verifier for a session token. */
export async function redeemSso(baseUrl: string, code: string, verifier: string, label: string): Promise<ServerConfig> {
  const res = await fetch(`${normalizeBaseUrl(baseUrl)}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sso: code, verifier, session: "token", label }),
  });
  const data = (await res.json().catch(() => null)) as { token?: string; error?: string } | null;
  if (res.ok && data?.token) return { baseUrl, token: data.token };
  throw new ApiError(data?.error ?? `HTTP ${res.status}`, res.status);
}

/**
 * Signs in through the server's SSO provider in the system browser (an in-app auth
 * session on iOS and Android, a popup on the web), returning to the `auth` route.
 */
export async function signInWithSso(baseUrl: string, providerId: string, label = "SuperBot app"): Promise<ServerConfig> {
  const redirect = ssoRedirect();
  const pkce = prepared ?? (await newPkce());
  prepared = null;
  prepareSso();
  const { verifier, challenge } = pkce;
  const state = randomString();
  const url = ssoStartUrl(baseUrl, providerId, { redirect, challenge, state, label });
  const result = await WebBrowser.openAuthSessionAsync(url, redirect);
  if (result.type !== "success") throw new Error(SSO_ERRORS.sso_cancelled);
  const back = parseSsoReturn(result.url, state);
  if ("error" in back) throw new Error(back.error);
  return redeemSso(baseUrl, back.code, verifier, label);
}
