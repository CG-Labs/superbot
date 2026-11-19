import { normalizeBaseUrl } from "./auth";

/** `scheme://host[:port]` of the server, lowercase. */
export function serverOrigin(baseUrl: string): string {
  const m = /^(https?:\/\/[^/?#\\@]+)(?:[/?#]|$)/i.exec(normalizeBaseUrl(baseUrl));
  if (!m) throw new Error("Bad server address");
  return m[1].toLowerCase();
}

/**
 * Turns the `url` from GET /api/bots/:id/screen into an absolute live-view link.
 * Only same-origin `/screen/<port>/...` paths are accepted, so a bad response can't
 * point the frame somewhere else. The link carries voxl's per-screen token, never
 * the server password.
 */
export function resolveScreenUrl(baseUrl: string, url: string): string {
  const origin = serverOrigin(baseUrl);
  let path: string;
  if (url.startsWith("/") && !url.startsWith("//")) {
    path = url;
  } else if (url.toLowerCase().startsWith(`${origin}/`)) {
    path = url.slice(origin.length);
  } else {
    throw new Error("Screen link is not on this server");
  }
  if (!/^\/screen\/\d+\/[^\\]*$/.test(path)) throw new Error("Unexpected screen link");
  return origin + path;
}

/** Whether the native live view may navigate to `url`: only pages on the server's origin. */
export function isAllowedScreenNavigation(origin: string, url: string): boolean {
  if (url === "about:blank" || url.startsWith("blob:") || url.startsWith("data:")) return true;
  return url.toLowerCase().startsWith(`${origin.toLowerCase()}/`);
}
