export type MessageRole = "user" | "bot" | "routine" | "peer" | "reply";

export interface QuestionCard {
  title: string;
  options: string[];
  handoff?: boolean;
  picked?: number | null;
}

export interface Message {
  id: number;
  botId: string;
  role: MessageRole;
  text: string;
  question?: QuestionCard;
  error?: boolean;
  fromBot?: string;
  at: number;
}

export interface BotView {
  id: string;
  name: string;
  color: string;
  shape: string;
  harness: string;
  model?: string | null;
  effort?: string | null;
  primary: boolean;
  hidden: boolean;
  unread: boolean;
  /** Id of the Bot's handoff card the user hasn't answered yet. */
  handoff?: number | null;
  preview?: string;
  working: boolean;
  status?: string;
  draft?: string;
  /** Effective harness policy: "ask" pauses risky tool calls for approval. */
  policy?: PolicyMode;
  /** True when this Bot overrides the global policy. */
  policyOverride?: boolean;
  /** Bot ACLs (ADR 0017). Servers from before send none of these. */
  owner?: { id: string; name: string } | null;
  visibility?: Visibility;
  /** What you may do with it. */
  access?: BotAccess;
  /** Where its runs go now (ADR 0046): this server, its owner's machine, or nowhere
   *  yet. Sent only when Bots can run on users' machines. */
  runsOn?: "server" | "machine" | "nowhere";
  /** "isolated": runs for anyone but its owner get their access and the server's keys,
   *  never the owner's own. Absent: it acts as its owner for everyone. */
  sharedBots?: "isolated";
  /** True when teammates log in its harness with their own account on its owner's
   *  machine (ADR 0062): their runs there never use the owner's login. */
  teammateLogins?: boolean;
  /** The owner's plan (ADR 0033). On a managed plan the server picks the model and
   *  sends `model` and `effort` only to admins. */
  tier?: TierBadge;
  /** Admins only: the route this Bot's runs take. */
  route?: { harness: string; provider?: string; model?: string | null; effort?: string };
  /** Admins only: the harnesses the owner's plan allows, for editing someone else's Bot. */
  harnesses?: string[];
  /** Suggested prompts in its details (ADR 0054). Null or absent: the defaults. */
  prompts?: string[] | null;
}

export interface TierBadge {
  name: string;
  label: string;
  managed: boolean;
}

/** A plan as anyone may see it: no model names. */
export interface TierView extends TierBadge {
  limits: {
    maxBots?: number | null;
    monthlyRuns?: number | null;
    monthlyTokens?: number | null;
    /** Routine runs a day, UTC (ADR 0040). */
    dailyRoutineRuns?: number | null;
    /** The machine size (provider plan) the control plane gives this plan's users. */
    machineType?: string | null;
  };
}

/** A plan with what the user has used of it (`/api/me/tier`, and admins' user views). */
export interface PlanUsage extends TierView {
  usage: {
    period: string;
    runs: number;
    bots: number;
    day?: string;
    routineRuns?: number;
    /** Model tokens this billing period (ADR 0050). Missing from older servers. */
    tokens?: number;
    periodStart?: number;
    periodEnd?: number;
    periodSource?: "subscription" | "calendar";
  };
}
/** Model tokens over some runs, as harnesses report them (ADR 0050). */
export interface TokenTotals {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  total: number;
  runs: number;
  /** Runs whose harness reported no tokens: not counted, not free. */
  unreportedRuns: number;
}
/** `GET /api/me/usage`: your model tokens and runs this billing period (ADR 0050). */
export interface MyUsage {
  user: string;
  tier: TierView;
  /** Your paid subscription's period, else the calendar month (UTC). Unix ms, end excluded. */
  period: { key: string; start: number; end: number; source: "subscription" | "calendar" };
  tokens: TokenTotals & { limit: number | null };
  runs: { used: number; limit: number | null };
  /** `name` is null for a Bot that was deleted, or that you no longer own. */
  byBot: (TokenTotals & { bot: string; name: string | null })[];
  /** Only when your plan lets you pick models (ADR 0033), or for admins. */
  byModel?: (TokenTotals & { model: string | null })[];
}

/** A plan for sale through Stripe Checkout (ADR 0042). */
export interface BillingPlan extends TierView {
  /** The plan the user is on now. */
  current: boolean;
}

/** `/api/billing`: your plan and use, the plans you can buy, and your billing account. */
export interface BillingView {
  plan: PlanUsage;
  plans: BillingPlan[];
  /** The subscription paying for your plan now, if one does. Change it in the portal. */
  subscription: { status: string; tier: string | null; periodEnd: number | null } | null;
  /** You have a Stripe customer, so "Manage billing" works. */
  portal: boolean;
  /** False for read-only people: they see their plan but can't buy or manage it. */
  canChange: boolean;
}

/** One of your own secrets, as `/api/me/secrets` lists it (ADR 0029, 0044). Never the value. */
export interface PersonalSecret {
  name: string;
  /** Unix seconds. Older servers send only `updatedAt`. */
  createdAt?: number;
  updatedAt: number;
  /** The server has a secret of this name for every Bot; yours wins for your Bots. */
  overrides?: boolean;
}

export type Visibility = "private" | "shared";
/** Each level includes the ones before it. */
export type BotAccess = "view" | "operate" | "manage";

/** `/api/bots/{id}/access`. Grants come only with "manage". */
export interface BotAccessView {
  botId: string;
  owner: { id: string; name: string | null; email: string | null };
  visibility: Visibility;
  access: BotAccess;
  grants?: { user: { id: string; name: string | null; email: string | null }; level: "viewer" | "operator" }[];
}

export type PolicyMode = "ask" | "bypass";
export type PolicyAction = "allow" | "ask" | "deny";

export interface Policy {
  mode: PolicyMode;
  classes: Record<string, PolicyAction>;
  timeoutMinutes: number;
  /** The harness's own sandbox (ADR 0055), on top of approvals. */
  sandbox: boolean;
}

/** A Bot's own settings on top of the global policy; missing fields follow it. */
export interface PolicyOverride {
  mode?: PolicyMode;
  classes?: Record<string, PolicyAction>;
  timeoutMinutes?: number;
  sandbox?: boolean;
}

/** A change to a policy. On a Bot, `null` puts that field back to following the global policy. */
export interface PolicyPatch {
  mode?: PolicyMode | null;
  classes?: Record<string, PolicyAction | null>;
  timeoutMinutes?: number | null;
  sandbox?: boolean | null;
}

/** Which harnesses have a sandbox of their own, and which of those can start it on the server. */
export interface SandboxSupport {
  harnesses: string[];
  available: string[];
}

export interface PolicyClass {
  id: string;
  label: string;
}

/** An allow or deny rule. `tool` is "*", a kind (shell, file, web, mcp, other), or a tool name. */
export interface PolicyRule {
  id: string;
  /** null: applies to every Bot. */
  botId: string | null;
  action: "allow" | "deny";
  tool: string;
  pattern: string;
  note: string | null;
  at: number;
}

export interface NewPolicyRule {
  botId?: string;
  action: "allow" | "deny";
  tool: string;
  pattern: string;
  note?: string;
}

/**
 * `/api/policy` (global rules only) or `/api/bots/{id}/policy`: the Bot's effective policy,
 * its override (null when it follows the global policy), and its rules plus the global ones.
 */
export interface PolicyView {
  policy: Policy;
  classes: PolicyClass[];
  rules: PolicyRule[];
  override?: PolicyOverride | null;
  /** Missing from an older server. */
  sandbox?: SandboxSupport;
}

// Approval notifications (ADR 0061): admins only.

export type NotifyFormat = "slack" | "json";
export type NotifyDetail = "summary" | "minimal";

export interface NotificationSettings {
  email: { enabled: boolean; to: string[]; deciders: boolean };
  webhook: { enabled: boolean; format: NotifyFormat };
  delaySeconds: number;
  throttleSeconds: number;
  detail: NotifyDetail;
}

/** A webhook URL is a secret: only whether it's set, and its host. */
export interface WebhookUrlView {
  set: boolean;
  host: string | null;
  store: string | null;
  /** False when the server's environment holds it, so it changes there. */
  writable: boolean;
}

export interface NotificationsView {
  settings: NotificationSettings;
  email: { configured: boolean; server: string | null; passwordSet: boolean };
  webhook: WebhookUrlView;
  signing: boolean;
  links: { app?: string | null; console?: string | null; problem?: string };
  /** Bots with settings of their own. */
  bots: string[];
}

export interface NotificationsPatch {
  email?: { enabled?: boolean; to?: string[]; deciders?: boolean };
  /** url: a string saves it, null removes it. */
  webhook?: { enabled?: boolean; format?: NotifyFormat; url?: string | null };
  delaySeconds?: number;
  throttleSeconds?: number;
  detail?: NotifyDetail;
}

/** Unset fields follow the global settings. */
export interface BotNotifySettings {
  email?: boolean;
  webhook?: boolean;
  format?: NotifyFormat;
}

export interface BotNotificationsView {
  botId: string;
  override: BotNotifySettings;
  webhook: WebhookUrlView;
  global: { email: boolean; webhook: boolean; format: NotifyFormat };
  /** Where its next notice goes, as things are now. */
  reaches: { email: number; deciders: { id: string; name: string; hasEmail: boolean }[]; webhook: "global" | "own" | null };
}

export interface BotNotificationsPatch {
  email?: boolean | null;
  webhook?: boolean | null;
  format?: NotifyFormat | null;
  webhookUrl?: string | null;
}

export interface NotifyTestResult {
  ok: boolean;
  results: { channel: string; ok: boolean; delivered?: number; error?: string | null }[];
}

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "cancelled";

export interface Approval {
  id: string;
  botId: string;
  harness: string;
  tool: string;
  kind: string;
  subject: string;
  class: string;
  reason: string;
  status: ApprovalStatus;
  createdAt: number;
  expiresAt: number;
  decidedAt?: number | null;
  decidedBy?: string | null;
  note?: string | null;
  /** The run the call came from, while it was the Bot's live run (ADR 0051). */
  runId?: string | null;
  /** What "Approve for this run" would cover. Null: this call can only be approved once. */
  runScope?: ApprovalRunScope | null;
  /** How it was approved: just this call, or for the rest of its run. */
  scope?: ApprovalScope | null;
}

export type ApprovalScope = "once" | "run";

export interface ApprovalRunScope {
  /** The kinds of call it lets through, e.g. "Pushes to a git remote". */
  covers: string[];
  /** True when it covers only this exact call again (deletes outside the workspace). */
  exact: boolean;
}

export interface ModelOption {
  id: string;
  label: string;
  efforts: string[];
  aliases?: string[];
}

export type Role = "admin" | "member" | "readonly";

/** A user as `/api/users` lists them (ADR 0012, 0021). Admins only. */
export interface AdminUser {
  id: string;
  email: string | null;
  name: string;
  role: Role;
  status: "active" | "disabled";
  /** The owner account: break-glass signs in as it. Can't be demoted or disabled. */
  breakGlass: boolean;
  createdAt: number;
  updatedAt: number;
  lastLoginAt?: number | null;
  /** How they last signed in, in the audit log's terms (ADR 0019). */
  lastLogin?: LastLogin | null;
  identities?: UserIdentity[];
  /** Codes made for this user and not used yet. Never the codes themselves. */
  pendingCodes?: { count: number; expiresAt: number } | null;
  /** Their plan and their use of it (ADR 0033, 0040). */
  plan?: PlanUsage;
}

export interface LastLogin {
  at: number;
  /** "password", "code", or "sso". */
  authMethod?: string | null;
  /** The SSO provider id it came through, and that provider's type ("entra", "google", …). */
  idpProvider?: string | null;
  idp?: string | null;
}

/** An SSO sign-in linked to a user (ADR 0014). */
export interface UserIdentity {
  id: string;
  provider: string;
  idp?: string | null;
  email?: string | null;
  subject?: string;
  createdAt: number;
  lastLoginAt?: number | null;
}

/** `POST /api/users/:id/login-codes`. The code is shown once; the server keeps only its hash. */
export interface LoginCode {
  code: string;
  expiresAt: number;
}

/** A request for access from the landing page (ADR 0022), as `/api/signups` lists it. Admins only. */
export interface SignupRequest {
  id: string;
  name: string;
  email: string;
  company: string;
  teamSize: string;
  useCase: string;
  /** The sign-in they'd like: "microsoft", "google", "github", "apple", or "other". */
  signIn: string;
  status: "pending" | "approved" | "rejected";
  createdAt: number;
  decidedAt?: number | null;
  reason?: string | null;
  userId?: string | null;
  /** A user has this email already, so approving would fail. */
  existingUser: boolean;
}

/** `POST /api/signups/:id/approve`: the new user and their code, shown once. */
export interface SignupApproval extends LoginCode {
  signup: SignupRequest;
  user: AdminUser;
  /** Configured SSO providers that fit the request; link one so they can skip codes. */
  sso: { id: string; label: string; type: string }[];
  emailed: boolean;
}

/** `GET /api/sessions?user=` */
export interface SessionView {
  id: string;
  kind: "cookie" | "token";
  method: string;
  idpProvider?: string | null;
  label?: string | null;
  createdAt: number;
  lastSeenAt: number;
  endsAt: number;
}

/** `GET /api/users/:id/bots`: what one user can reach, per ADR 0017. */
export interface UserBots {
  active: boolean;
  bots: {
    bot: { id: string; name: string; color: string; shape: string };
    owner: { id: string; name: string | null };
    visibility: Visibility;
    access: BotAccess;
    grant: "viewer" | "operator" | null;
  }[];
}

/** One row of `/api/audit` (ADR 0009, 0019). Admins only. Actor fields are null on rows from before ADR 0019. */
export interface AuditEvent {
  id: number;
  /** Unix ms. */
  at: number;
  /** `at` as RFC 3339 UTC. */
  time: string;
  actorKind: "user" | "bot" | "system";
  actorId?: string | null;
  actorName?: string | null;
  /** The IdP subject, `<issuer>|<sub>`, after an SSO sign-in. */
  actorSubject?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  botId?: string | null;
  outcome: "success" | "failure" | "denied";
  ip?: string | null;
  userAgent?: string | null;
  details?: Record<string, unknown> | null;
  actorEmail?: string | null;
  actorRole?: string | null;
  /** "password" (break-glass), "code", "sso", "none", or "bot_token". */
  authMethod?: string | null;
  idp?: string | null;
  idpProvider?: string | null;
  sessionId?: string | null;
  /** The user a Bot or the scheduler acted for. */
  onBehalfOf?: string | null;
}

/** `GET /api/audit`: newest first. Pass `nextBefore` back as `before` for the next page. */
export interface AuditPage {
  events: AuditEvent[];
  nextBefore: number | null;
}

/** `GET /api/setup` (admins, ADR 0034): the parts the client uses. The wizard itself is in the console. */
export interface SetupStatus {
  progress: { step: string; show: boolean; dismissed: boolean; completedAt: number | null };
  checklist: { id: string; label: string; done: boolean; detail: string }[];
  done: number;
  total: number;
}

/** `/api/state` `me`. Servers from before ADR 0012 send only the name. */
export interface Me {
  name: string;
  id?: string | null;
  email?: string | null;
  role?: Role | "bot";
  permissions?: string[];
  session?: boolean;
  tier?: TierView;
}

export interface AppState {
  me: Me;
  harnesses: string[];
  defaultHarness: string;
  bots: BotView[];
  policy?: Policy;
  approvals?: Approval[];
}

export interface Routine {
  id: string;
  bot_id: string;
  name: string;
  cron: string;
  instruction: string;
  enabled: boolean;
  last_run_at?: number | null;
  created_at?: number;
}

export type SseEvent =
  | { type: "message"; message: Message; bot?: BotView }
  | { type: "bot"; bot: BotView }
  | { type: "botDeleted"; botId: string }
  | { type: "draft"; botId: string; text: string }
  | { type: "status"; botId: string; working: boolean; status?: string }
  | { type: "approval"; approval: Approval }
  | { type: "policy"; policy: Policy }
  | { type: "resync" };

/**
 * A session token (servers with sign-in, ADR 0012), the legacy shared password, or, on
 * the web build the server hosts, the browser's own session cookie from its sign-in
 * page (ADR 0027). The cookie is never readable here, so it is never saved.
 */
export interface ServerConfig {
  baseUrl: string;
  token?: string;
  password?: string;
  cookie?: boolean;
}
/** A harness login, as one person's runs on a machine see it (ADR 0041, 0062). */
export type HarnessLoginState = "logged_in" | "logged_out" | "logging_in";

export interface TeammateHarnessLogin {
  state: HarnessLoginState;
  /** When the login was saved (Unix ms), if there is one. */
  since?: number | null;
  /** A server-wide key logs your runs in without a login of your own. */
  serverKey: boolean;
}

/** Your own harness logins on a teammate's machine (ADR 0062). */
export interface TeammateLoginsView {
  machineId: string;
  owner: { id: string; name: string | null } | null;
  forUser: string;
  logins: "on";
  /** You have your own user on the machine yet. */
  hasUser: boolean;
  harnesses: Record<string, TeammateHarnessLogin>;
}

/** What a running login sends, one per line. */
export type LoginEvent =
  | { type: "started"; loginId: string }
  | { type: "output"; text: string }
  | { type: "ping" }
  | { type: "exit"; success: boolean; status: string; loggedIn: boolean }
  | { type: "error"; message: string };
