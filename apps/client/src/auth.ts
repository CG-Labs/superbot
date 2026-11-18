import { encode as b64encode } from "base-64";
import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";

const SERVER_KEY = "superbot.server";
const PASSWORD_KEY = "superbot.password";

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

export async function loadSavedCredentials(): Promise<{ baseUrl: string; password: string } | null> {
  const baseUrl = await storeGet(SERVER_KEY);
  const password = await storeGet(PASSWORD_KEY);
  if (!baseUrl || password == null) return null;
  return { baseUrl, password };
}

export async function saveCredentials(baseUrl: string, password: string): Promise<void> {
  await storeSet(SERVER_KEY, normalizeBaseUrl(baseUrl));
  await storeSet(PASSWORD_KEY, password);
}

export async function clearCredentials(): Promise<void> {
  await storeDelete(SERVER_KEY);
  await storeDelete(PASSWORD_KEY);
}