import { encode as b64encode } from "base-64";
import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";
import type { ServerConfig } from "./types";

const SERVER_KEY = "superbot.server";
const PASSWORD_KEY = "superbot.password";
const TOKEN_KEY = "superbot.token";

async function storeSet(key: string, value: string): Promise<void> {
  if (Platform.OS === "web") {
    if (typeof localStorage !== "undefined") localStorage.setItem(key, value);
    return;
  }
  await SecureStore.setItemAsync(key, value);
}

async function storeGet(key: string): Promise<string | null> {
  if (Platform.OS === "web") {
    if (typeof localStorage === "undefined") return null;
    return localStorage.getItem(key);
  }
  return SecureStore.getItemAsync(key);
}

async function storeDelete(key: string): Promise<void> {
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

export function basicAuthHeader(password: string, username = "superbot"): string {
  return `Basic ${b64encode(`${username}:${password}`)}`;
}

/** Bearer for a session token; Basic for the legacy shared password. */
export function authHeader(cfg: ServerConfig): string {
  return cfg.token ? `Bearer ${cfg.token}` : basicAuthHeader(cfg.password ?? "");
}

export async function loadSavedCredentials(): Promise<ServerConfig | null> {
  const baseUrl = await storeGet(SERVER_KEY);
  if (!baseUrl) return null;
  const token = await storeGet(TOKEN_KEY);
  if (token) return { baseUrl, token };
  const password = await storeGet(PASSWORD_KEY);
  return password == null ? null : { baseUrl, password };
}

/** Saves a token in place of the password, so the password stops living on the device. */
export async function saveCredentials(cfg: ServerConfig): Promise<void> {
  await storeSet(SERVER_KEY, normalizeBaseUrl(cfg.baseUrl));
  if (cfg.token) {
    await storeSet(TOKEN_KEY, cfg.token);
    await storeDelete(PASSWORD_KEY);
  } else {
    await storeSet(PASSWORD_KEY, cfg.password ?? "");
    await storeDelete(TOKEN_KEY);
  }
}

export async function clearCredentials(): Promise<void> {
  await storeDelete(SERVER_KEY);
  await storeDelete(PASSWORD_KEY);
  await storeDelete(TOKEN_KEY);
}
