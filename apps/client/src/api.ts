import { authHeader, basicAuthHeader, normalizeBaseUrl } from "./auth";
import type { AppState, Approval, BotView, Message, ModelOption, Policy, PolicyMode, Routine, ServerConfig } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** One-time sign-in codes an admin makes start with this (see ADR 0012). */
export const CODE_PREFIX = "sbc_";

/**
 * Signs in with a password or sign-in code and returns a session-token config.
 * Servers from before sign-in (ADR 0012) don't have the endpoint: with a password,
 * fall back to sending it on every request, as before.
 */
export async function signIn(baseUrl: string, secret: string, label = "SuperBot app"): Promise<ServerConfig> {
  const isCode = secret.startsWith(CODE_PREFIX);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  // Lets an old server, which checks auth before routing, answer 404 instead of 401.
  if (!isCode) headers.Authorization = basicAuthHeader(secret);
  const res = await fetch(`${normalizeBaseUrl(baseUrl)}/api/auth/login`, {
    method: "POST",
    headers,
    body: JSON.stringify({ ...(isCode ? { code: secret } : { password: secret }), session: "token", label }),
  });
  const data = (await res.json().catch(() => null)) as { token?: string; error?: string } | null;
  if (res.ok && data?.token) return { baseUrl, token: data.token };
  if (res.status === 404 || res.status === 405) {
    if (isCode) throw new ApiError("This server doesn't support sign-in codes. Use the password.", res.status);
    return { baseUrl, password: secret };
  }
  if (res.status === 401 && !data?.error) {
    throw new ApiError(isCode ? "This server doesn't support sign-in codes. Use the password." : "Wrong password.", 401);
  }
  throw new ApiError(data?.error ?? `HTTP ${res.status}`, res.status);
}

export class SuperBotApi {
  constructor(private cfg: ServerConfig) {}

  get config(): ServerConfig {
    return this.cfg;
  }

  get baseUrl(): string {
    return normalizeBaseUrl(this.cfg.baseUrl);
  }

  private headers(json = false): Record<string, string> {
    const h: Record<string, string> = {
      Authorization: authHeader(this.cfg),
    };
    if (json) h["Content-Type"] = "application/json";
    return h;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(body !== undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = (data as { error?: string }).error ?? `HTTP ${res.status}`;
      throw new ApiError(msg, res.status);
    }
    return data as T;
  }

  async verify(): Promise<AppState> {
    return this.request<AppState>("GET", "/api/state");
  }

  /** Ends this session on the server. Nothing to end for a password config. */
  async logout(): Promise<void> {
    if (this.cfg.token) await this.request("POST", "/api/auth/logout");
  }

  async createBot(body: {
    name: string;
    color: string;
    shape: string;
    harness: string;
  }): Promise<BotView> {
    return this.request<BotView>("POST", "/api/bots", body);
  }

  async patchBot(id: string, body: Record<string, unknown>): Promise<BotView> {
    return this.request<BotView>("PATCH", `/api/bots/${id}`, body);
  }

  async deleteBot(id: string): Promise<void> {
    await this.request("DELETE", `/api/bots/${id}`);
  }

  async messages(id: string): Promise<Message[]> {
    return this.request<Message[]>("GET", `/api/bots/${id}/messages`);
  }

  async sendMessage(
    id: string,
    text: string,
    answer?: { messageId: number; option: number },
  ): Promise<Message> {
    return this.request<Message>("POST", `/api/bots/${id}/messages`, { text, answer });
  }

  async markRead(id: string): Promise<void> {
    await this.request("POST", `/api/bots/${id}/read`);
  }

  async stopBot(id: string): Promise<void> {
    await this.request("POST", `/api/bots/${id}/stop`);
  }

  async models(harness: string): Promise<ModelOption[]> {
    return this.request<ModelOption[]>("GET", `/api/harnesses/${harness}/models`);
  }

  async routines(botId: string): Promise<Routine[]> {
    return this.request<Routine[]>("GET", `/api/bots/${botId}/routines`);
  }

  async createRoutine(
    botId: string,
    body: { name: string; cron: string; instruction: string; enabled?: boolean },
  ): Promise<Routine> {
    return this.request<Routine>("POST", `/api/bots/${botId}/routines`, body);
  }

  async patchRoutine(id: string, body: Record<string, unknown>): Promise<Routine> {
    return this.request<Routine>("PATCH", `/api/routines/${id}`, body);
  }

  async deleteRoutine(id: string): Promise<void> {
    await this.request("DELETE", `/api/routines/${id}`);
  }

  /** Starts the Bot's screen and returns its live view link (see `resolveScreenUrl`). */
  async screen(botId: string): Promise<{ url: string }> {
    return this.request<{ url: string }>("GET", `/api/bots/${botId}/screen`);
  }

  async decideApproval(id: string, approve: boolean, remember: boolean): Promise<Approval> {
    return this.request<Approval>("POST", `/api/approvals/${id}/${approve ? "approve" : "deny"}`, {
      remember: remember ? "bot" : null,
    });
  }

  async setGlobalPolicy(mode: PolicyMode): Promise<Policy> {
    return (await this.request<{ policy: Policy }>("PUT", "/api/policy", { mode })).policy;
  }

  /** mode null drops the Bot's override, so it follows the global policy again. */
  async setBotPolicy(botId: string, mode: PolicyMode | null): Promise<void> {
    if (mode) await this.request("PUT", `/api/bots/${botId}/policy`, { mode });
    else await this.request("DELETE", `/api/bots/${botId}/policy`);
  }

  eventsUrl(): string {
    return `${this.baseUrl}/api/events`;
  }

  authHeaders(): Record<string, string> {
    return this.headers();
  }
}