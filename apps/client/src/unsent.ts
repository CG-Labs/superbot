/** Failed sends of one signed-in session, kept outside the chat so they survive it closing. */
export interface Unsent {
  /** Each Bot's failed messages, oldest first, waiting for an empty message box. */
  words: Record<string, string[]>;
  /** Each Bot's failed send whose Retry toast is still live. */
  retries: Record<string, { body: string; toast: number }>;
  /** Signed out: nothing is kept, retried or shown for this session any more. */
  ended: boolean;
}

const bySession = new WeakMap<object, Unsent>();

/** The session's saved sends; with no session, a throwaway that keeps nothing. */
export function unsentFor(session: object | null): Unsent {
  if (!session) return { words: {}, retries: {}, ended: true };
  let u = bySession.get(session);
  if (!u) bySession.set(session, (u = { words: {}, retries: {}, ended: false }));
  return u;
}

/** Keeps a failed message for its Bot; `first` puts it before the others (it failed earlier). */
export function keepWords(u: Unsent, botId: string, body: string, first = false): void {
  if (u.ended) return;
  const list = (u.words[botId] ??= []);
  if (list.includes(body)) return;
  if (first) list.unshift(body);
  else list.push(body);
}

/** Takes all of a Bot's failed messages, joined for the message box, or null when there are none. */
export function takeWords(u: Unsent, botId: string): string | null {
  const list = u.words[botId];
  delete u.words[botId];
  return list?.length ? list.join("\n\n") : null;
}

/** Forgets one failed message once it's been sent again. */
export function forgetWords(u: Unsent, botId: string, body: string): void {
  const list = u.words[botId];
  if (!list) return;
  const i = list.indexOf(body);
  if (i >= 0) list.splice(i, 1);
  if (!list.length) delete u.words[botId];
}

/** Forgets a signed-out session's words, so they never reach the next account on this device. */
export function endUnsent(session: object | null): void {
  if (!session) return;
  const u = unsentFor(session);
  u.ended = true;
  u.words = {};
  u.retries = {};
}
