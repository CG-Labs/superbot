import { approvalParam } from "./notifications";
import type { PushView } from "./types";

/** What the phone lets SuperBot do (the OS permission), as the device adapter reports it. */
export type PushPermission = "granted" | "denied" | "undetermined";

/** Where a tapped push opens. Only these places, whatever the payload says. */
export type PushLink = { pathname: "/home"; params: { approval: string } } | { pathname: "/home"; params: { bot: string } } | { pathname: "/home" } | { pathname: "/team" } | { pathname: "/settings" };

/** The project id `app.json` ships with until whoever builds the app sets a real one. */
export const PLACEHOLDER_PROJECT_ID = "00000000-0000-4000-8000-000000000001";

/** A Bot id from a link (`/home?bot=<id>`), when it looks like one. */
export function botParam(v: string | string[] | undefined): string | null {
  const id = Array.isArray(v) ? v[0] : v;
  return id && /^[A-Za-z0-9_-]{1,64}$/.test(id) ? id : null;
}

/**
 * Where a push's data sends a tap (ADR 0080): an approval opens the inbox on it, a
 * routine opens its Bot's chat, a request for a team role opens Team (ADR 0302), and
 * your own request being decided opens Settings, where it's listed (ADR 0329).
 * Pushes carry only ids; the app fetches the rest.
 * Anything else opens home, and nothing that isn't SuperBot's opens at all.
 */
export function pushLink(data: unknown): PushLink | null {
  if (!data || typeof data !== "object") return null;
  const d = data as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : undefined);
  switch (d.type) {
    case "approval": {
      const approval = approvalParam(str(d.approvalId));
      return approval ? { pathname: "/home", params: { approval } } : { pathname: "/home" };
    }
    case "routine": {
      const bot = botParam(str(d.botId));
      return bot ? { pathname: "/home", params: { bot } } : { pathname: "/home" };
    }
    case "role_request":
      return { pathname: "/team" };
    case "role_decision":
      return { pathname: "/settings" };
    case "test":
      return { pathname: "/home" };
    default:
      return null;
  }
}

/** Why this build can't get a push token, or null. Whoever builds the app sets the EAS project. */
export function projectProblem(projectId: string | undefined | null): string | null {
  if (!projectId || projectId === PLACEHOLDER_PROJECT_ID) {
    return "This build of the app can't get push notifications: it has no Expo project. Whoever builds it sets one (see ADR 0080).";
  }
  return null;
}

export const BLOCKED = "Notifications are blocked for SuperBot. Allow them in your phone's settings, then try again.";

/** The card's state in a line, for what it can't offer. Null when push can be turned on. */
export function pushUnavailable(view: PushView | undefined, supported: boolean): string | null {
  if (!supported) return "Push notifications work in the iPhone and Android apps. Here, pending approvals show in the inbox.";
  if (view && !view.available) return "Push notifications are off on this server. An admin can turn them on (PUSH_PROVIDER=expo).";
  return null;
}
