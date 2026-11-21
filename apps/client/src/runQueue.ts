import type { BotView } from "./types";

type Status = Pick<BotView, "working" | "status" | "queued">;

/** Whether the Bot's run is waiting for a free slot on its computer (ADR 0073). */
export function isQueued(bot: Status): boolean {
  return bot.working && bot.queued?.reason === "at_capacity";
}

/** The Bot's status line while it works: a queued run says where it is in line and why. */
export function workingLabel(bot: Status): string {
  const q = bot.queued;
  if (!isQueued(bot) || !q?.position || !q.limit) return bot.status || "Working";
  const place = q.host === "machine" ? "its computer" : "this server";
  const line = q.position === 1 ? "next in line" : `#${q.position} in line`;
  const tasks = q.limit === 1 ? "task" : "tasks";
  return `Queued, ${line}: ${place} runs ${q.limit} ${tasks} at once`;
}
