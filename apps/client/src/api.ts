import { authHeader, basicAuthHeader, normalizeBaseUrl } from "./auth";
import type {
  AdminUser,
  AppState,
  Approval,
  ApprovalScope,
  AuditPage,
  BillingView,
  BotAccessView,
  BotNotificationsPatch,
  BotNotificationsView,
  BotView,
  LoginCode,
  Message,
  ModelOption,
  MyUsage,
  NewPolicyRule,
  NotificationsPatch,
  NotificationsView,
  NotifyTestResult,
  PersonalSecret,
  Policy,
  PolicyMode,
  PolicyPatch,
  PolicyRule,
  PolicyView,
  PushRegistration,
  PushView,
  Role,
  Routine,
  ServerConfig,
  SessionView,
  SetupStatus,
  SignupApproval,
  SignupRequest,
  TeammateAccounts,
  TeammateLoginsView,
  TeammateRemoval,
  UserBots,
  UserIdentity,
  Visibility,
} from "./types";
import type { LoginEvent } from "./types";
import { streamLogin, teammateLoginPath, type LoginStream, type StreamXhr } from "./teammateLogins";

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

/**
 * The session the server's sign-in page (or a web SSO sign-in) left in this browser, when
 * this web build is served by that server: those pages send people here (ADR 0027).
 */
export async function cookieSession(baseUrl: string, timeoutMs = 5000): Promise<ServerConfig | null> {
  // Startup waits on this, so a server that never answers must not hide the sign-in form.
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(`${normalizeBaseUrl(baseUrl)}/api/auth/me`, { credentials: "same-origin", signal: ctl.signal });
    if (!res.ok) return null;
    const me = (await res.json()) as { session?: unknown } | null;
    return me?.session ? { baseUrl, cookie: true } : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export class SuperBotApi {
  /** Called when the server refuses this session token, e.g. after a revoke. */
  onSessionEnded?: () => void;

  constructor(private cfg: ServerConfig) {}

  get config(): ServerConfig {
    return this.cfg;
  }

  get baseUrl(): string {
    return normalizeBaseUrl(this.cfg.baseUrl);
  }

  private headers(json = false): Record<string, string> {
    const h: Record<string, string> = {};
    const auth = authHeader(this.cfg);
    if (auth) h.Authorization = auth;
    if (json) h["Content-Type"] = "application/json";
    return h;
  }

  /** A session the server can end: a token, or the browser's cookie. */
  get hasSession(): boolean {
    return !!(this.cfg.token || this.cfg.cookie);
  }

  private async send(method: string, path: string, body?: unknown): Promise<Response> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(body !== undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      if (res.status === 401 && this.hasSession) this.onSessionEnded?.();
      const msg = (data as { error?: string }).error ?? `HTTP ${res.status}`;
      throw new ApiError(msg, res.status);
    }
    return res;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.send(method, path, body);
    return (await res.json().catch(() => ({}))) as T;
  }

  async verify(): Promise<AppState> {
    return this.request<AppState>("GET", "/api/state");
  }

  /** Ends the session on the server, giving up after `timeoutMs`. Nothing to end for a password config. */
  async logout(timeoutMs = 5000): Promise<void> {
    if (!this.hasSession) return;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}/api/auth/logout`, { method: "POST", headers: this.headers(false), signal: ctl.signal });
      // 401: the session was already gone.
      if (!res.ok && res.status !== 401) throw new ApiError(`Sign-out failed (${res.status})`, res.status);
    } finally {
      clearTimeout(timer);
    }
  }

  async createBot(body: {
    name: string;
    color: string;
    shape: string;
    /** Unset: the server's default for the owner's plan (ADR 0079). */
    harness?: string;
  }): Promise<BotView> {
    return this.request<BotView>("POST", "/api/bots", body);
  }

  async patchBot(id: string, body: Record<string, unknown>): Promise<BotView> {
    return this.request<BotView>("PATCH", `/api/bots/${id}`, body);
  }

  async deleteBot(id: string): Promise<void> {
    await this.request("DELETE", `/api/bots/${id}`);
  }

  /** Who can see a Bot (ADR 0017). Owner changes are for admins. */
  async patchBotAccess(id: string, body: { visibility?: Visibility; owner?: string }): Promise<BotAccessView> {
    return this.request<BotAccessView>("PATCH", `/api/bots/${id}/access`, body);
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

  /** `tier` (admins): only that plan's models. */
  async models(harness: string, tier?: string): Promise<ModelOption[]> {
    return this.request<ModelOption[]>("GET", `/api/harnesses/${harness}/models${tier ? `?tier=${encodeURIComponent(tier)}` : ""}`);
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

  /** scope "run" also approves calls of the same kind for the rest of the run (ADR 0051). */
  async decideApproval(id: string, approve: boolean, remember: boolean, scope: ApprovalScope = "once"): Promise<Approval> {
    return this.request<Approval>("POST", `/api/approvals/${id}/${approve ? "approve" : "deny"}`, {
      remember: remember ? "bot" : null,
      scope,
    });
  }

  async setGlobalPolicy(mode: PolicyMode): Promise<Policy> {
    return (await this.request<{ policy: Policy }>("PUT", "/api/policy", { mode })).policy;
  }

  /** mode null drops the Bot's override, so it follows the global policy again. */
  async setBotPolicy(botId: string, mode: PolicyMode | null): Promise<void> {
    if (mode) await this.request("PUT", `/api/bots/${botId}/policy`, { mode });
    else await this.resetBotPolicy(botId);
  }

  // The policy editor (ADR 0049). Anyone signed in reads; only admins change it.

  /** The global policy with its rules, or one Bot's (which needs view access to it). */
  async policyView(botId?: string): Promise<PolicyView> {
    if (botId) return this.request<PolicyView>("GET", `/api/bots/${botId}/policy`);
    return this.request<PolicyView>("GET", "/api/policy");
  }

  async patchGlobalPolicy(patch: PolicyPatch): Promise<Policy> {
    return (await this.request<{ policy: Policy }>("PUT", "/api/policy", patch)).policy;
  }

  async patchBotPolicy(botId: string, patch: PolicyPatch): Promise<PolicyView> {
    return this.request<PolicyView>("PUT", `/api/bots/${botId}/policy`, patch);
  }

  async resetBotPolicy(botId: string): Promise<PolicyView> {
    return this.request<PolicyView>("DELETE", `/api/bots/${botId}/policy`);
  }

  async addPolicyRule(rule: NewPolicyRule): Promise<PolicyRule> {
    return this.request<PolicyRule>("POST", "/api/policy/rules", rule);
  }

  async deletePolicyRule(id: string): Promise<void> {
    await this.request("DELETE", `/api/policy/rules/${encodeURIComponent(id)}`);
  }

  // Approval notifications (ADR 0061): admins only, enforced by the server.

  async notifications(): Promise<NotificationsView> {
    return this.request<NotificationsView>("GET", "/api/notifications");
  }

  async patchNotifications(patch: NotificationsPatch): Promise<NotificationsView> {
    return this.request<NotificationsView>("PUT", "/api/notifications", patch);
  }

  /** Sends a test now through every channel that's on: the global settings, or one Bot's. */
  async testNotifications(botId?: string): Promise<NotifyTestResult> {
    return this.request<NotifyTestResult>("POST", "/api/notifications/test", botId ? { botId } : {});
  }

  /** Whether this server sends push, and this session's phone (ADR 0080). */
  async pushDevice(): Promise<PushView> {
    return this.request<PushView>("GET", "/api/me/push");
  }

  /** Registers this phone for this session, in place of any it had. */
  async registerPush(body: PushRegistration): Promise<PushView> {
    return this.request<PushView>("PUT", "/api/me/push", body);
  }

  async unregisterPush(): Promise<PushView> {
    return this.request<PushView>("DELETE", "/api/me/push");
  }

  async botNotifications(botId: string): Promise<BotNotificationsView> {
    return this.request<BotNotificationsView>("GET", `/api/bots/${botId}/notifications`);
  }

  async patchBotNotifications(botId: string, patch: BotNotificationsPatch): Promise<BotNotificationsView> {
    return this.request<BotNotificationsView>("PUT", `/api/bots/${botId}/notifications`, patch);
  }

  // Users, codes, sessions, and sign-ins: admins only, enforced by the server (ADR 0012, 0021).

  async users(): Promise<AdminUser[]> {
    return this.request<AdminUser[]>("GET", "/api/users");
  }

  async createUser(body: { email: string; name?: string; role: Role }): Promise<AdminUser> {
    return this.request<AdminUser>("POST", "/api/users", body);
  }

  async patchUser(id: string, body: { name?: string; role?: Role; status?: "active" | "disabled" }): Promise<AdminUser> {
    return this.request<AdminUser>("PATCH", `/api/users/${encodeURIComponent(id)}`, body);
  }

  /** `replace` drops the user's unused codes first, so only the new one works. */
  async createLoginCode(id: string, ttlMinutes: number, replace = false): Promise<LoginCode> {
    return this.request<LoginCode>("POST", `/api/users/${encodeURIComponent(id)}/login-codes`, { ttlMinutes, replace });
  }

  async userSessions(id: string): Promise<SessionView[]> {
    return this.request<SessionView[]>("GET", `/api/sessions?user=${encodeURIComponent(id)}`);
  }

  /** Ends all of a user's sessions and drops their unused codes. */
  async revokeUserSessions(id: string): Promise<{ revoked: number }> {
    return this.request<{ revoked: number }>("DELETE", `/api/users/${encodeURIComponent(id)}/sessions`);
  }

  async linkIdentity(id: string, body: { provider: string; subject: string; tenant?: string }): Promise<UserIdentity> {
    return this.request<UserIdentity>("POST", `/api/users/${encodeURIComponent(id)}/identities`, body);
  }

  async unlinkIdentity(id: string, identityId: string): Promise<void> {
    await this.request("DELETE", `/api/users/${encodeURIComponent(id)}/identities/${encodeURIComponent(identityId)}`);
  }

  async userBots(id: string): Promise<UserBots> {
    return this.request<UserBots>("GET", `/api/users/${encodeURIComponent(id)}/bots`);
  }

  /** Teammates' own accounts on this server around the user (ADR 0066). null when teammates have none here. */
  async teammateAccounts(id: string): Promise<TeammateAccounts | null> {
    try {
      return await this.request<TeammateAccounts>("GET", `/api/users/${encodeURIComponent(id)}/teammate-accounts`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) return null;
      throw err;
    }
  }

  /** Removes `teammate`'s account for `owner`'s Bots now; `error` says why when it's still pending. */
  async removeTeammateAccount(owner: string, teammate: string): Promise<{ removal: TeammateRemoval | null; error?: string }> {
    return this.request("POST", `/api/users/${encodeURIComponent(owner)}/teammate-accounts/${encodeURIComponent(teammate)}/remove`);
  }

  /** The onboarding wizard's progress and checklist: admins only (ADR 0034). The wizard is in the console. */
  async setupStatus(): Promise<SetupStatus> {
    return this.request<SetupStatus>("GET", "/api/setup");
  }

  // Your own plan, bought and managed on Stripe's pages (ADR 0042).

  /**
   * Your plan, what you can buy, and your billing account. null when this server doesn't
   * sell plans: it answers 404, or, from before billing, 403 to anyone but admins.
   */
  async billing(): Promise<BillingView | null> {
    try {
      return await this.request<BillingView>("GET", "/api/billing");
    } catch (e) {
      if (e instanceof ApiError && [403, 404, 405].includes(e.status)) return null;
      throw e;
    }
  }

  /** Your model tokens and runs this billing period. null from servers before ADR 0050. */
  async myUsage(): Promise<MyUsage | null> {
    try {
      return await this.request<MyUsage>("GET", "/api/me/usage");
    } catch (e) {
      if (e instanceof ApiError && [403, 404, 405].includes(e.status)) return null;
      throw e;
    }
  }

  /** A Stripe Checkout page for the plan; open `url` to pay. */
  async checkout(tier: string): Promise<{ url: string }> {
    return this.request<{ url: string }>("POST", "/api/billing/checkout", { tier });
  }

  /** Your Stripe billing portal: change or cancel the plan, cards, invoices. */
  async billingPortal(): Promise<{ url: string }> {
    return this.request<{ url: string }>("POST", "/api/billing/portal");
  }

  // Your own secrets, for your Bots only (ADR 0029, 0044). Values go in, never come back.

  async mySecrets(): Promise<PersonalSecret[]> {
    return (await this.request<{ secrets: PersonalSecret[] }>("GET", "/api/me/secrets")).secrets ?? [];
  }

  /** Saves a new secret, or replaces the value of one you have. */
  async setMySecret(name: string, value: string): Promise<PersonalSecret> {
    return (await this.request<{ secret: PersonalSecret }>("PUT", `/api/me/secrets/${encodeURIComponent(name)}`, { value })).secret;
  }

  async deleteMySecret(name: string): Promise<void> {
    await this.request("DELETE", `/api/me/secrets/${encodeURIComponent(name)}`);
  }

  // Your own harness logins on a teammate's machine (ADR 0062). Theirs is never used for you.

  async teammateLogins(ownerId: string): Promise<TeammateLoginsView> {
    return this.request<TeammateLoginsView>("GET", teammateLoginPath(ownerId, "harness-logins"));
  }

  /** Starts a login of yours there; its terminal's events come to `onEvent`. */
  startTeammateLogin(
    ownerId: string,
    harness: string,
    onEvent: (e: LoginEvent) => void,
    make: () => StreamXhr = () => new XMLHttpRequest() as unknown as StreamXhr,
  ): LoginStream {
    return streamLogin(make, `${this.baseUrl}${teammateLoginPath(ownerId, "harness-login")}`, this.headers(true), harness, onEvent);
  }

  /** Types a line into your running login there. */
  async teammateLoginInput(ownerId: string, loginId: string, text: string): Promise<void> {
    await this.request("POST", teammateLoginPath(ownerId, `harness-login/${encodeURIComponent(loginId)}/input`), { text });
  }

  async stopTeammateLogin(ownerId: string, loginId: string): Promise<void> {
    await this.request("DELETE", teammateLoginPath(ownerId, `harness-login/${encodeURIComponent(loginId)}`));
  }

  /** Removes your login there. */
  async teammateLogout(ownerId: string, harness: string): Promise<TeammateLoginsView> {
    return this.request<TeammateLoginsView>("DELETE", teammateLoginPath(ownerId, `harness-logins/${encodeURIComponent(harness)}`));
  }

  // Requests for access from the landing page: admins only (ADR 0022).

  async signups(status: SignupRequest["status"] | "all" = "pending"): Promise<SignupRequest[]> {
    return this.request<SignupRequest[]>("GET", `/api/signups?status=${status}`);
  }

  /** Makes the user and a one-time code, returned once. */
  async approveSignup(id: string, body: { role: Role; ttlMinutes: number }): Promise<SignupApproval> {
    return this.request<SignupApproval>("POST", `/api/signups/${encodeURIComponent(id)}/approve`, body);
  }

  /** The reason is for admins; nobody is told. */
  async rejectSignup(id: string, reason?: string): Promise<SignupRequest> {
    return this.request<SignupRequest>("POST", `/api/signups/${encodeURIComponent(id)}/reject`, { reason: reason || null });
  }

  // The audit log: admins only (ADR 0009, 0019). `query` comes from `auditQuery`.

  async audit(query: string, before?: number | null, limit = 100): Promise<AuditPage> {
    const page = [query, before != null && `before=${before}`, `limit=${limit}`].filter(Boolean).join("&");
    return this.request<AuditPage>("GET", `/api/audit?${page}`);
  }

  /**
   * The filtered log as CSV, oldest first. Fetched with this session's credentials
   * rather than linked, since a bearer token can't ride on a plain link.
   */
  async auditCsv(query: string): Promise<string> {
    const res = await this.send("GET", `/api/audit/export.csv${query ? `?${query}` : ""}`);
    return res.text();
  }

  eventsUrl(): string {
    return `${this.baseUrl}/api/events`;
  }

  authHeaders(): Record<string, string> {
    return this.headers();
  }
}