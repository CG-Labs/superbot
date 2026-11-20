import { Linking } from "react-native";
import type { SuperBotApi } from "./api";
import { normalizeBaseUrl } from "./auth";
import type { Me } from "./types";

/**
 * Admins get the console and the audit log; the server lands only them on `/console/`
 * (ADR 0027) and refuses its admin API to everyone else. Servers from before roles send
 * no permissions, and have no console.
 */
export function isAdmin(me: Me): boolean {
  return !!me.permissions?.includes("admin");
}

export function consoleUrl(baseUrl: string): string {
  return `${normalizeBaseUrl(baseUrl)}/console/`;
}

/**
 * A new tab on web (same origin when the server hosts this build); the system browser on
 * phones. The console signs in with a browser cookie, so phones sign in there once.
 */
export function openConsole(baseUrl: string): Promise<void> {
  return Linking.openURL(consoleUrl(baseUrl));
}

/** The console's onboarding wizard (ADR 0034). */
export function setupUrl(baseUrl: string): string {
  return `${consoleUrl(baseUrl)}#setup`;
}

export function openSetup(baseUrl: string): Promise<void> {
  return Linking.openURL(setupUrl(baseUrl));
}

/**
 * Whether to point this admin at the setup wizard: until an admin finishes or hides it.
 * Never for anyone else, and not when the server is older than the wizard or can't say.
 */
export async function setupPending(api: Pick<SuperBotApi, "setupStatus">, me: Me): Promise<boolean> {
  if (!isAdmin(me)) return false;
  try {
    return (await api.setupStatus()).progress?.show === true;
  } catch {
    return false;
  }
}
