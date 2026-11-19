import { encode as b64encode } from "base-64";
import * as Crypto from "expo-crypto";
import * as Linking from "expo-linking";
import * as WebBrowser from "expo-web-browser";
import { Platform } from "react-native";
import { ApiError } from "./api";
import { normalizeBaseUrl } from "./auth";
import type { ServerConfig } from "./types";

/** A single sign-on provider the server offers (ADR 0013). */
export interface SsoProvider {
  id: string;
  label: string;
  type: string;
}

/** Messages for the fixed error codes the server sends back. */
export const SSO_ERRORS: Record<string, string> = {
  sso_not_linked: "Your account isn't set up on this server yet. Ask an admin to add you.",
  sso_not_allowed: "Your SuperBot account is disabled.",
  sso_email_taken: "A user with your email already exists. Ask an admin to link your sign-in to it.",
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

/** The providers on this server; none when it's older or unreachable. */
export async function fetchSsoProviders(baseUrl: string): Promise<SsoProvider[]> {
  try {
    const res = await fetch(`${normalizeBaseUrl(baseUrl)}/api/auth/sso`);
    if (!res.ok) return [];
    const data = (await res.json()) as { providers?: SsoProvider[] };
    return Array.isArray(data.providers) ? data.providers : [];
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
  const redirect = Linking.createURL("auth");
  const { verifier, challenge } = await newPkce();
  const state = randomString();
  const url = ssoStartUrl(baseUrl, providerId, { redirect, challenge, state, label });
  const result = await WebBrowser.openAuthSessionAsync(url, redirect);
  if (result.type !== "success") throw new Error(SSO_ERRORS.sso_cancelled);
  const back = parseSsoReturn(result.url, state);
  if ("error" in back) throw new Error(back.error);
  return redeemSso(baseUrl, back.code, verifier, label);
}
