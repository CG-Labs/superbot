import type { Message } from "./types";

/** Open handoffs, at most one per Bot: botId -> the latest unanswered handoff card. */
export type HandoffMap = Record<string, Message>;

export function isHandoff(m: Message): boolean {
  return m.role === "bot" && m.question?.handoff === true;
}

export function isOpenHandoff(m: Message): boolean {
  return isHandoff(m) && m.question?.picked == null;
}

/**
 * The Bot's latest handoff the user still has to act on. A handoff stops being open
 * once it's answered or the user has sent a later message (they moved on; the Bot
 * gets that message instead).
 */
export function latestOpenHandoff(list: Message[]): Message | undefined {
  for (let i = list.length - 1; i >= 0; i--) {
    const m = list[i];
    if (m.role === "user") return undefined;
    if (isOpenHandoff(m)) return m;
  }
  return undefined;
}

/** Applies one live message to the open-handoff map. */
export function applyHandoffMessage(map: HandoffMap, m: Message): HandoffMap {
  if (isOpenHandoff(m)) return { ...map, [m.botId]: m };
  const open = map[m.botId];
  if (m.role === "user" && open && m.id > open.id) return withoutHandoff(map, m.botId);
  return map;
}

/** Replaces one Bot's entry after its history loads. */
export function applyHandoffHistory(map: HandoffMap, botId: string, list: Message[]): HandoffMap {
  const open = latestOpenHandoff(list);
  if (open) return { ...map, [botId]: open };
  return map[botId] ? withoutHandoff(map, botId) : map;
}

export function withoutHandoff(map: HandoffMap, botId: string, messageId?: number): HandoffMap {
  if (!map[botId] || (messageId != null && map[botId].id !== messageId)) return map;
  const next = { ...map };
  delete next[botId];
  return next;
}

/** Marks a question card as answered in a message list. */
export function withPicked(list: Message[], messageId: number, option: number | null): Message[] {
  return list.map((m) =>
    m.id === messageId && m.question ? { ...m, question: { ...m.question, picked: option } } : m,
  );
}
