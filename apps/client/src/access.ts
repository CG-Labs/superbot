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
