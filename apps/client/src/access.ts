import type { BotAccess, BotView } from "./types";

const RANK: Record<BotAccess, number> = { view: 1, operate: 2, manage: 3 };

/**
 * Your access to a Bot (ADR 0017). Servers from before Bot ACLs don't say; there,
 * your role alone decided.
 */
export function botAccess(bot: Pick<BotView, "access"> | null | undefined, canWrite: boolean): BotAccess {
  return bot?.access ?? (canWrite ? "manage" : "view");
}

/** Whether you may do what takes `need` on this Bot. The server enforces it; this hides what would fail. */
export function hasAccess(bot: Pick<BotView, "access"> | null | undefined, need: BotAccess, canWrite: boolean): boolean {
  if (need !== "view" && !canWrite) return false;
  return RANK[botAccess(bot, canWrite)] >= RANK[need];
}

/** Who can see it, in a few words. */
export function sharingLabel(bot: Pick<BotView, "visibility" | "owner">, meId?: string | null): string {
  const owner = bot.owner ? (bot.owner.id === meId ? "you" : bot.owner.name) : null;
  const who = bot.visibility === "private" ? "Private" : "Shared with everyone";
  return owner ? `${who} · owned by ${owner}` : who;
}

/** Where its runs happen (ADR 0046). Null when the server doesn't say: always on the server. */
export function whereItRuns(bot: Pick<BotView, "runsOn" | "owner">, meId?: string | null): string | null {
  if (!bot.runsOn) return null;
  const whose = !bot.owner ? "its owner's" : bot.owner.id === meId ? "your" : `${bot.owner.name}'s`;
  if (bot.runsOn === "machine") return `Runs on ${whose} computer`;
  if (bot.runsOn === "server") return `Runs on this server, in ${whose} folder`;
  return `Can't run yet: ${whose} computer isn't set up`;
}

/** Which of its owner's service accounts made and keeps it (ADR 0222). Null for a person's Bot. */
export function keptBy(bot: Pick<BotView, "serviceAccount">): string | null {
  if (!bot.serviceAccount) return null;
  return `Kept by service account ${bot.serviceAccount.name}: its runs reach only what that account may`;
}

/** What a run for someone other than its owner gets, when the server isolates them.
 *  With `teammateLogins` (ADR 0062) that includes their own harness login. */
export function whoseKeys(bot: Pick<BotView, "sharedBots" | "owner" | "visibility" | "teammateLogins">, meId?: string | null): string | null {
  if (bot.sharedBots !== "isolated" || !bot.owner) return null;
  const login = bot.teammateLogins;
  if (bot.owner.id !== meId) {
    return `For you it uses ${login ? "your own login or " : ""}the server's keys and your access, never ${bot.owner.name}'s own`;
  }
  if (bot.visibility !== "shared") return null;
  return `Others' runs use ${login ? "their own login or " : ""}the server's keys and their access, never your own`;
}
