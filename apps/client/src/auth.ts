import { encode as b64encode } from "base-64";
import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";
import type { ServerConfig } from "./types";

const SERVER_KEY = "superbot.server";
const PASSWORD_KEY = "superbot.password";
const TOKEN_KEY = "superbot.token";

/** The keychain / keystore on phones; `localStorage` on web and Electron. */
export async function storeSet(key: string, value: string): Promise<void> {
  if (Platform.OS === "web") {
    if (typeof localStorage !== "undefined") localStorage.setItem(key, value);
    return;
  }
  await SecureStore.setItemAsync(key, value);
}

export async function storeGet(key: string): Promise<string | null> {
  if (Platform.OS === "web") {
    if (typeof localStorage === "undefined") return null;
    return localStorage.getItem(key);
  }
  return SecureStore.getItemAsync(key);
}

export async function storeDelete(key: string): Promise<void> {
  if (Platform.OS === "web") {
    if (typeof localStorage !== "undefined") localStorage.removeItem(key);
    return;
  }
  await SecureStore.deleteItemAsync(key);
}

export function normalizeBaseUrl(input: string): string {
  const trimmed = input.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(trimmed)) {
    return `http://${trimmed}`;
  }
  return trimmed;
}

export const LOCAL_SERVER_URL = "http://127.0.0.1:3000";

/**
 * A web build served over http(s) is hosted by the SuperBot server itself (Caddy serves it
 * beside botd), so that origin is the server. Dev servers and Electron (file://) are not.
 */
export function defaultServerUrl(
  os: string = Platform.OS,
  location: { protocol?: string; origin?: string } | undefined = typeof window === "undefined" ? undefined : window.location,
  dev: boolean = __DEV__,
): string {
  if (os === "web" && !dev && location?.origin && /^https?:$/.test(location.protocol ?? "")) {
    return location.origin;
  }
  return LOCAL_SERVER_URL;
}

export function basicAuthHeader(password: string, username = "superbot"): string {
  return `Basic ${b64encode(`${username}:${password}`)}`;
}

/** Bearer for a session token; Basic for the legacy shared password; none for a cookie session. */
export function authHeader(cfg: ServerConfig): string | null {
  if (cfg.token) return `Bearer ${cfg.token}`;
  return cfg.cookie ? null : basicAuthHeader(cfg.password ?? "");
}

export async function loadSavedCredentials(): Promise<ServerConfig | null> {
  const baseUrl = await storeGet(SERVER_KEY);
  if (!baseUrl) return null;
  const token = await storeGet(TOKEN_KEY);
  if (token) return { baseUrl, token };
  const password = await storeGet(PASSWORD_KEY);
  return password == null ? null : { baseUrl, password };
}

/**
 * Saves a token in place of the password, so the password stops living on the device.
 * Servers from before sign-in only take the password: it goes in the keychain on
 * phones and is never written to browser storage, so the web app asks again on reload.
 */
export async function saveCredentials(cfg: ServerConfig): Promise<void> {
  await storeSet(SERVER_KEY, normalizeBaseUrl(cfg.baseUrl));
  if (cfg.token) {
    await storeSet(TOKEN_KEY, cfg.token);
    await storeDelete(PASSWORD_KEY);
  } else {
    await storeDelete(TOKEN_KEY);
    await storeDelete(PASSWORD_KEY);
    if (Platform.OS !== "web") await SecureStore.setItemAsync(PASSWORD_KEY, cfg.password ?? "");
  }
}

/**
 * Set on sign-out from a cookie session and cleared once the server confirms it, or by
 * the next sign-in (here, on `/login`, or a web SSO sign-in). While set, a cookie the
 * server never got to clear is ended instead of being taken up again (ADR 0027).
 */
export const SIGNED_OUT_KEY = "superbot.signedOut";

export async function setCookieSignedOut(on: boolean): Promise<void> {
  if (on) await storeSet(SIGNED_OUT_KEY, "1");
  else await storeDelete(SIGNED_OUT_KEY);
}

export async function cookieSignedOut(): Promise<boolean> {
  return (await storeGet(SIGNED_OUT_KEY)) === "1";
}

export async function clearCredentials(): Promise<void> {
  await storeDelete(SERVER_KEY);
  await storeDelete(PASSWORD_KEY);
  await storeDelete(TOKEN_KEY);
}
