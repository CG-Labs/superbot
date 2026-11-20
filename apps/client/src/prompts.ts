import type { BotView } from "./types";

/** The server's limits (ADR 0054). */
export const MAX_PROMPTS = 6;
export const MAX_PROMPT_CHARS = 200;

/** Shown when a Bot has none saved. Bots have no role or description, so these are
 *  the console's two starters plus one that works for any Bot with a computer. */
export const DEFAULT_PROMPTS = ["Set up a routine to…", "Your job is to…", "What can you do on your computer?"];

const ELLIPSIS = /(…|\.\.\.)$/;

/** The prompts a Bot's details offer: its own, or the defaults when it has none saved. */
export function promptsFor(bot: Pick<BotView, "prompts">): string[] {
  return bot.prompts ?? DEFAULT_PROMPTS;
}

/** A prompt ending in "…" is a starter: it goes in the message box for the user to
 *  finish. Any other prompt is sent as it is. */
export function isStarter(prompt: string): boolean {
  return ELLIPSIS.test(prompt.trim());
}

/** A starter as it goes in the message box: without its "…", ready to type on. */
export function starterText(prompt: string): string {
  return `${prompt.trim().replace(ELLIPSIS, "").trimEnd()} `;
}

/** The list as the server would save it: trimmed, no blanks, no repeats. */
export function cleanPrompts(list: string[]): string[] {
  const out: string[] = [];
  for (const p of list.map((x) => x.trim())) {
    if (p && !out.includes(p)) out.push(p);
  }
  return out;
}

/** Why the server would refuse this list, or null. */
export function validatePrompts(list: string[]): string | null {
  if (list.some((p) => [...p.trim()].length > MAX_PROMPT_CHARS)) {
    return `A prompt can be at most ${MAX_PROMPT_CHARS} characters`;
  }
  if (cleanPrompts(list).length > MAX_PROMPTS) return `A Bot can have at most ${MAX_PROMPTS} suggested prompts`;
  return null;
}
