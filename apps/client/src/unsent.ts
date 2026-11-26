/** Failed sends of one signed-in session, kept outside the chat so they survive it closing. */
export interface Unsent {
  /** Words per Bot, waiting for an empty message box. */
  words: Record<string, string>;
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

/** Forgets a signed-out session's words, so they never reach the next account on this device. */
export function endUnsent(session: object | null): void {
  if (!session) return;
  const u = unsentFor(session);
  u.ended = true;
  u.words = {};
  u.retries = {};
}
