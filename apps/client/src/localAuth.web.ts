import type { LocalAuth } from "./localAuth";

/** Browsers and Electron have no biometric API here, so App lock is unavailable (ADR 0078). */
export const localAuth: LocalAuth = {
  probe: async () => null,
  authenticate: async () => ({ success: false, error: "not_available" }),
};
