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
  /** Set while its run waits for a free slot on the computer it runs on (ADR 0073). */
  queued?: RunQueue;
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

/** A run waiting its turn: the computer runs `limit` at once and `running` are going. */
export interface RunQueue {
  reason: "at_capacity" | "starting";
  host: "server" | "machine";
  position?: number;
  running?: number;
  limit?: number;
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
    /** Bot runs at once on this plan's machines; more wait their turn (ADR 0073). */
    concurrentRuns?: number | null;
    /** Storage for one user's files, in MB of 1,000,000 bytes (ADR 0082). */
    maxStorageMb?: number | null;
  };
}

/** A user's storage against their plan's cap (ADR 0082). Sizes in bytes; null until measured. */
export interface StorageUsage {
  used: number | null;
  files?: number | null;
  data?: number | null;
  limit: number | null;
  limitMb?: number | null;
  percent: number | null;
  state: "ok" | "warning" | "over" | null;
  /** The percentage from which people are warned. */
  warnAt: number;
  /** Some folders couldn't be read, or the machine hasn't said yet: the number is a lower bound. */
  partial: boolean;
  measuredAt: number | null;
  /** Their Bots work on their own machine: its homes count instead of the workspace (ADR 0105). */
  onMachine?: boolean;
  /** What that machine last said its homes hold, however old (ADR 0105). */
  machine?: MachineStorage | null;
}

/** A machine's report of its homes (ADR 0105): `used` is null until it first says. */
export interface MachineStorage {
  used: number | null;
  report: "fresh" | "stale" | "missing";
  partial: boolean;
  measuredAt: number | null;
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
    /** Missing from servers before ADR 0082. */
    storage?: StorageUsage;
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
  /** Missing from servers before ADR 0082. */
  storage?: StorageUsage;
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
  /** Billing emails (ADR 0091). Missing from older servers. */
  emails?: BillingEmails;
  /** Your team pays for your plan (ADR 0093): then it's the team's, changed on the Team screen. */
  teamPlan?: { id: string; name: string | null; tier: string | null; periodEnd: number | null } | null;
}

/** `/api/me/emails`: whether this server sends billing emails, and whether you get the usage ones. */
export interface BillingEmails {
  /** The server sends billing emails at all. */
  on: boolean;
  /** You get the token and storage limit emails. Plan and payment emails always go. */
  usage: boolean;
  /** False for read-only people. Only from `/api/me/emails`. */
  canChange?: boolean;
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
  /** Push (ADR 0080): the provider when an operator turned it on; each person opts in per phone. */
  push?: { provider: string | null; accessTokenSet: boolean };
  links: { app?: string | null; console?: string | null; problem?: string };
  /** Bots with settings of their own. */
  bots: string[];
}

/** This session's phone for push notifications (ADR 0080). The token never comes back. */
export interface PushDeviceView {
  id: string;
  platform: "ios" | "android";
  approvals: boolean;
  routines: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface PushView {
  /** Whether this server sends push at all. */
  available: boolean;
  provider: string | null;
  device: PushDeviceView | null;
}

export interface PushRegistration {
  token: string;
  platform: "ios" | "android";
  approvals?: boolean;
  routines?: boolean;
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
  /** Their second factor (ADR 0094). */
  mfa?: { enabled: boolean; enabledAt: number | null };
  /** Their custom role across the server (ADR 0123); its base is `role`. */
  roleId?: string | null;
  customRole?: CustomRoleRef | null;
  /** What they can do across the server: their role's permissions and their custom role's (ADR 0132). */
  permissions?: string[];
}

/** A custom role, named (ADR 0123). */
export interface CustomRoleRef {
  id: string;
  name: string;
}

/** A permission a custom role can hold; `team` ones also apply when given within a team. */
export interface RolePermission {
  name: string;
  description: string;
  team: boolean;
}

/** A built-in role, as a preset of permissions. Can't be changed. */
export interface BuiltInRole {
  id: Role;
  name: string;
  builtIn: true;
  permissions: string[];
}

export type RoleBase = Exclude<Role, "admin">;

/** A custom role (ADR 0123): a base plus delegable permissions. */
export interface CustomRole {
  id: string;
  name: string;
  description: string;
  base: RoleBase;
  builtIn: false;
  permissions: string[];
  /** Names this server doesn't know, saved by another version: shown, never granted. */
  unknown: string[];
  /** Its base's permissions and its own. */
  effective: string[];
  /** How many people have it across the server, and within a team. */
  users: number;
  teamMembers: number;
  createdAt: number;
  createdBy: string | null;
  updatedAt: number;
  /** Only from `GET /api/roles/{id}`. */
  holders?: {
    users: { id: string; name: string; email: string | null }[];
    teams: { team: { id: string; name: string }; user: { id: string; name: string; email: string | null } }[];
  };
}

/** `GET /api/roles`. */
export interface RolesView {
  permissions: RolePermission[];
  builtIn: BuiltInRole[];
  roles: CustomRole[];
}

/** Someone named in an admin view. */
export interface PersonRef {
  id: string;
  name: string;
  email: string | null;
}

/** A service account (ADR 0143): a non-human caller that acts only through its tokens. Never an admin. */
export interface ServiceAccount {
  id: string;
  name: string;
  description: string;
  role: RoleBase;
  status: "active" | "disabled";
  /** Its custom role across the server; null within a team. */
  customRole: CustomRoleRef | null;
  team: { id: string; name: string } | null;
  /** Its custom role within `team`. */
  teamRole: CustomRoleRef | null;
  owner: PersonRef | null;
  /** False once the owner is disabled or gone: they lend nothing, so its tokens are refused. */
  ownerActive: boolean;
  /** What it holds across the server, and within its team. */
  permissions: string[];
  teamPermissions: string[];
  /** What its tokens can use today: what it holds, within what its owner holds now. */
  effective: string[];
  /** Live tokens. */
  tokens: number;
  lastUsedAt: number | null;
  createdAt: number;
  createdBy: string | null;
  updatedAt: number;
  /** Only from `GET /api/service-accounts/{id}`, newest first. */
  tokenList?: ServiceToken[];
}

/** A service account's API token, never its secret. */
export interface ServiceToken {
  id: string;
  accountId: string;
  name: string;
  /** `sbsa_…` and its last four characters. */
  preview: string;
  /** Null: all its account holds. */
  scopes: string[] | null;
  state: "active" | "expired" | "revoked";
  createdAt: number;
  createdBy: string | null;
  expiresAt: number;
  lastUsedAt: number | null;
  lastUsedIp: string | null;
  revokedAt: number | null;
  revokedBy: string | null;
  revokedReason: string | null;
  /** The token that replaced it; it may still work until `expiresAt`. */
  rotatedTo: string | null;
}

/** `GET /api/service-accounts`. */
export interface ServiceAccountsView {
  serviceAccounts: ServiceAccount[];
  /** Every permission a token can be scoped to. */
  scopes: string[];
  defaultDays: number;
  maxDays: number;
}

/** The form for `POST /api/service-accounts`, and `PATCH` with what changed. */
export interface ServiceAccountDraft {
  name: string;
  description: string;
  /** `member`, `readonly`, or a custom role's id. */
  role: string;
  /** A team's id, or "" for across the server. */
  team: string;
  /** The owner's email or id; only admins change it. */
  owner: string;
}

/** The reply to making or rotating a token: the only time its secret is sent. */
export interface MintedServiceToken {
  token: string;
  tokenInfo: ServiceToken;
  serviceAccount: { id: string; name: string };
  /** On rotate: the old token, and when it stops. */
  replaced?: { id: string; endsAt: number };
}

/** `POST /api/roles`, and `PATCH` with any of it. */
export interface RoleDraft {
  name: string;
  description: string;
  base: RoleBase;
  permissions: string[];
}

/** Who must have a second factor to sign in with a code or password (ADR 0094). */
export type MfaPolicy = "off" | "admins" | "all";

/** `GET /api/auth/mfa`: your own second factor, and the policy. */
export interface MfaStatus {
  enabled: boolean;
  enabledAt: number | null;
  /** Set up but not confirmed with a code yet. */
  pending: boolean;
  recoveryCodesLeft: number;
  /** The policy requires one for you. */
  required: boolean;
  policy: MfaPolicy;
  /** Set by AUTH_MFA on the server, so it can't be changed here. */
  policyPinned: boolean;
}

/** A key to add to an authenticator app. */
export interface MfaSetup {
  /** Base32, to type in. */
  secret: string;
  otpauthUrl: string;
  /** The otpauth URL as a QR code, an SVG document. */
  qrSvg: string;
}

/** A code from the app, or a recovery code. */
export type MfaProof = { totp: string } | { recoveryCode: string };

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
  /** The second factor it was signed in with: "totp" or "recovery_code". */
  mfa?: string | null;
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

/** A removal of a leaving teammate's account on this server (ADR 0066). */
export interface TeammateRemoval {
  id: string;
  ownerId: string;
  userId: string;
  account: string;
  reason: string;
  files: "archive" | "delete";
  state: "pending" | "held" | "done" | "cancelled";
  attempts: number;
  lastError: string | null;
  archivedTo: string | null;
  purgeAt: number | null;
  createdAt: number;
  doneAt: number | null;
  owner: { id: string; name?: string | null; email?: string | null };
  teammate: { id: string; name?: string | null; email?: string | null };
}

/** `/api/users/{id}/teammate-accounts`: teammates' own accounts for the user's shared Bots here, and the user's for others' (ADR 0064, 0066). */
export interface TeammateAccounts {
  userId: string;
  /** `ISOLATION_TEAMMATE_FILES`: what becomes of a removed teammate's work. */
  files: "archive" | "delete";
  /** `ISOLATION_TEAMMATE_FILES_DAYS`: with `delete`, how long it's held first. */
  graceDays: number;
  accounts: {
    owner: { id: string; name?: string | null; email?: string | null };
    teammate: { id: string; name?: string | null; email?: string | null };
    account: string;
    /** They still may use the owner's Bots. */
    wanted: boolean;
    removal: TeammateRemoval | null;
  }[];
  removals: TeammateRemoval[];
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

/** A row on the audit log's hash chain and its hash (ADR 0122). */
export interface ChainLink {
  id: number;
  hash: string;
}

/** A signed checkpoint of the chain's head, and its RFC 3161 timestamp (ADR 0149). */
export interface AuditCheckpoint {
  /** The `audit.checkpoint` event that carries it. */
  id: number;
  at: number;
  /** The event it signs, and that event's hash. */
  seq: number;
  hash: string;
  keyId: string;
  publicKey: string;
  signature: string;
  statement: string;
  timestamp: {
    /** "off" (no TSA when it was made), "pending" or "stamped". */
    status: "off" | "pending" | "stamped";
    tsa: string | null;
    time: number | null;
    tries: number;
    error: string | null;
  };
}

/** The last `audit.verified` check. */
export interface AuditVerification {
  id: number;
  at: number;
  by: string | null;
  ok: boolean;
  /** Why it failed: `contents`, `link`, `pin`, `checkpoint`, `timestamp`, ... */
  reason: string | null;
  checked: number;
  broken: number;
  firstBroken: { id: number; reason: string } | null;
  /** Set when only part of the log was checked (`--from`/`--to`); null bounds are open. */
  range?: { from: number | null; to: number | null } | null;
}

/** The SIEM export's progress (`GET /api/audit/siem`). */
export type AuditExportState =
  | { enabled: false }
  | { enabled: true; kind: string; sink: string; delivered: number; pending: number; deliveredAt: number | null; failing: boolean; lastError: string | null; archive?: AuditArchiveState };

/** The S3 archive's settings and last object, when the export is `s3://` (ADR 0154). */
export interface AuditArchiveState {
  endpoint: string;
  bucket: string;
  prefix: string;
  lock: "bucket" | "compliance" | "governance" | "off";
  retainDays: number | null;
  batchSeconds: number;
  lastObject: { key: string; version: string | null; events: number; lockMode?: string; retainUntil?: number } | null;
}

/** `GET /api/audit/chain`: the chain's state for admins (ADR 0149). */
export interface AuditChainState {
  head: ChainLink | null;
  events: number;
  anchor: ChainLink | null;
  checkpoints: {
    everyMinutes: number;
    count: number;
    key: { id: string; publicKey: string; algorithm: string };
    last: AuditCheckpoint | null;
    /** Events since the last checkpoint. */
    behind: number;
  };
  timestamps: {
    enabled: boolean;
    tsa: string | null;
    trustAnchors: number;
    stamped: number;
    pending: number;
    failing: boolean;
    failingSince: number | null;
    lastError: string | null;
    last: { checkpoint: number; event: number | null; time: number | null; tsa: string | null } | null;
  };
  export: AuditExportState;
  verification: AuditVerification | null;
}

/** `GET /api/audit/verify`: a check of the chain, its checkpoints and timestamps. */
export interface AuditVerifyReport {
  ok: boolean;
  checked: number;
  broken: number;
  firstBroken: { id: number; reason: string } | null;
  head: ChainLink | null;
  error?: string;
  checkpoints?: {
    checked: number;
    timestamped: number;
    trustedTimestamps: number | null;
    broken: number;
    firstBroken: { id: number; reason: string; error: string } | null;
  };
}

/** A live sign-in in the access review: metadata only, never the token. */
export interface AccessReviewSession {
  id: string;
  /** "cookie" (the web app) or "token" (a bearer token: the client, botctl). */
  kind: string;
  method: string;
  idpProvider?: string | null;
  label?: string | null;
  createdAt: number;
  lastSeenAt: number;
  endsAt: number;
  mfa?: string | null;
}

/** One person in `GET /api/access-review` (ADR 0099). */
export interface AccessReviewPerson {
  id: string;
  name: string;
  email: string | null;
  role: Role;
  status: "active" | "disabled";
  breakGlass: boolean;
  tier?: string | null;
  createdAt: number;
  /** The SCIM tenant that manages them, if any. */
  scim: { tenant: string; deleted: boolean } | null;
  team: { id: string; name: string; role: string } | null;
  mfa: { enabled: boolean; enabledAt: number | null };
  lastLogin: { at: number; method: string | null; idpProvider: string | null } | null;
  /** Admins reach every Bot by role, so `all` is set and `bots` is empty. */
  botAccess: {
    all: boolean;
    bots: { id: string; name: string; owner: { id: string; name: string | null }; own: boolean; visibility: string; access: string; grant: string | null }[];
  };
  sessions: AccessReviewSession[];
  apiTokens: AccessReviewSession[];
  machine: { id: string; provider: string; state: string; enrollment: string; assignedAt: number | null } | null;
}

export interface AccessReviewSignOff {
  eventId: number;
  at: number;
  time: string;
  reviewer: { id: string | null; name: string | null; email: string | null; role: string | null; method: string | null };
  digest: string;
  summary: AccessReviewSummary | null;
  notes: string | null;
}

export interface AccessReviewSummary {
  people: number;
  active: number;
  disabled: number;
  admins: number;
  activeWithoutMfa: number;
  scimManaged: number;
  browserSessions: number;
  apiAccess: number;
  machines: number;
}

/** `GET /api/access-review` (admins, ADR 0099): everyone, by SCIM tenant then team, and past sign-offs. */
export interface AccessReview {
  generatedAt: number;
  generatedTime: string;
  /** Names exactly this access; a sign-off sends it back. */
  digest: string;
  summary: AccessReviewSummary;
  groups: { tenant: string | null; team: { id: string; name: string } | null; people: AccessReviewPerson[] }[];
  reviews: AccessReviewSignOff[];
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
  | { type: "status"; botId: string; working: boolean; status?: string; queued?: RunQueue }
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
  /** Null when the owner's Bots run on this server, as your own account there (ADR 0064). */
  machineId: string | null;
  /** Where your login is kept: the owner's computer, or this server. Unset: the computer. */
  on?: "machine" | "server";
  owner: { id: string; name: string | null } | null;
  forUser: string;
  logins: "on";
  /** You have your own user there (on this server, your account for the owner's Bots) yet. */
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

// Team accounts (ADR 0087, 0088): your own team, from `GET /api/team`.

export type TeamRole = "owner" | "admin" | "member";

/** A teammate's machine as the team's owners and admins see it: its lifecycle, never its address, files, logins or screens. */
export interface TeamMachine {
  state: string;
  tier: string;
  region: string;
  enrollment: string;
  agentSeenAt: number | null;
  assigned: boolean;
  backups: boolean;
  lastBackupAt: number | null;
  createdAt: number;
  /** The team gave it, so the team manages it; else it's the teammate's own. */
  team: boolean;
  /** Set once they've left: when the released machine is destroyed. */
  releaseAt: number | null;
}

export interface TeamMember {
  id: string;
  name: string | null;
  email: string | null;
  role: TeamRole;
  joinedAt: number;
  active: boolean;
  /** A custom role given within this team (ADR 0123): only its team permissions apply here. */
  customRole?: CustomRoleRef | null;
  /** Only for the team's owners and admins; null when they have none. */
  machine?: TeamMachine | null;
}

export interface TeamInvite {
  id: string;
  teamId: string;
  email: string;
  role: TeamRole;
  createdAt: number;
  createdBy: string | null;
  expiresAt: number;
}

export interface Team {
  id: string;
  name: string;
  /** Joining gives a machine. */
  machines: boolean;
  createdAt: number;
  members: TeamMember[];
  /** Your role in it. */
  role?: TeamRole;
  /** Owners and admins only. */
  invites?: TeamInvite[];
  /** Owners and admins only: how long a leaver's team machine is kept suspended. */
  machineDays?: number;
  /** The team's plan (ADR 0093), while this server sells them. */
  billing?: TeamBilling;
  /** Where members' machines and backups live (ADR 0117), unless one has their own; null is the server's default. */
  region?: string | null;
}

/** A team's plan, paid for by the team for everyone on it (ADR 0093). Never a Stripe id. */
export interface TeamBilling {
  /** The plan the team pays for; null while it pays for none. */
  plan: { name: string; label: string } | null;
  /** Owners and admins only, from here down. */
  subscription?: { status: string; tier: string | null; periodEnd: number | null; cancelAt: number | null } | null;
  /** Seats Stripe bills, against the people on the team; null while nothing pays. */
  seats?: { members: number; billed: number | null; syncing: boolean; error: string | null } | null;
  /** The team has a Stripe customer, so "Manage billing" works. */
  portal?: boolean;
  plans?: TierView[];
  /** You manage the team and may change its plan. */
  canChange?: boolean;
}

/** An invite waiting for you, from `GET /api/me/team-invites`. */
export interface MyTeamInvite {
  id: string;
  team: { id: string; name: string | null };
  role: TeamRole;
  expiresAt: number;
}

export interface WorkPolicy {
  files: "archive" | "delete";
  graceDays: number;
}

/** What taking a teammate off the team would do, from `GET /api/team/members/{user}/offboarding`. */
export interface OffboardingPreview {
  user: { id: string; name: string | null };
  role: TeamRole;
  allowed: boolean;
  blocked: "self" | "owner" | null;
  /** Grants between them and teammates that end. */
  grants: number;
  machine: { fate: "suspend" | "destroy" | "kept" | "none"; days?: number };
  /** What becomes of their work: on teammates' machines, and on their accounts on this server. Each null when that cleanup is off. */
  work: { machines: WorkPolicy | null; accounts: WorkPolicy | null };
}

/** The residency pin on your data, and where your data is against it (`GET /api/me/residency`, ADR 0168). */
export interface MyResidency {
  /** Your team's pin, else your own; null when nothing pins your data. */
  pin: {
    on: "user" | "team";
    region: string;
    /** Unix ms. */
    pinnedAt: number;
    /** The agreement it is under: your own pin's, or your team's for its owners and admins. */
    reference?: string;
    team?: { id: string; name: string | null };
  } | null;
  /** Your own pin, when your team's holds your data too. */
  ownPin: { region: string; pinnedAt: number; reference: string } | null;
  status?: "kept" | "data_outside";
  machine?: { id: string; state: string; region: string; inRegion: boolean } | null;
  backups?: { kept: number; inRegion: number; outside: number };
  modelRoutes?: { inRegion: boolean; gap: string | null };
  /** The pins whose residency report you can get. */
  reports: ("user" | "team")[];
}
