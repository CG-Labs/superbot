import { basicAuthHeader, normalizeBaseUrl } from "./auth";
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

export class SuperBotApi {
  constructor(private cfg: ServerConfig) {}

  get baseUrl(): string {
    return normalizeBaseUrl(this.cfg.baseUrl);
  }

  private headers(json = false): Record<string, string> {
    const h: Record<string, string> = {
      Authorization: basicAuthHeader(this.cfg.password),
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

  async patchRoutine(id: string, body: Record<string, unknown>): Promise<Routine> {
    return this.request<Routine>("PATCH", `/api/routines/${id}`, body);
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