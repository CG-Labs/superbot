import { ApiError } from "./api";

export const OFFLINE_TEXT = "Can't reach the server. Check your connection and try again.";

/** What fetch throws when the request never reached the server, by browser and platform. */
const NETWORK = /failed to fetch|network request failed|networkerror|load failed|network error|internet connection/i;

/**
 * Plain words for an error, for people rather than logs. The server's own messages are
 * already written for people and pass through; bare status codes and network failures don't.
 */
export function friendlyError(err: unknown, fallback = "Something went wrong. Try again."): string {
  if (err instanceof ApiError) {
    if (!/^HTTP \d+$/.test(err.message)) return err.message;
    if (err.status === 401) return "Your session ended. Sign in again.";
    if (err.status === 403) return "You don't have access to that.";
    if (err.status === 404) return "That isn't there anymore.";
    if (err.status === 429) return "Too many tries. Wait a moment and try again.";
    if (err.status >= 500) return "The server had a problem. Try again in a moment.";
    return fallback;
  }
  if (err instanceof Error) {
    if (NETWORK.test(err.message)) return OFFLINE_TEXT;
    return err.message.trim() || fallback;
  }
  return fallback;
}

/** What failed, then why: "Couldn't load routines. Can't reach the server…". */
export function errorText(err: unknown, what?: string): string {
  const why = friendlyError(err, "");
  if (!what) return why || "Something went wrong. Try again.";
  return why ? `${what}. ${why}` : `${what}.`;
}
