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

/** `/api/state` `me`. Servers from before ADR 0012 send only the name. */
export interface Me {
  name: string;
  id?: string | null;
  email?: string | null;
  role?: Role | "bot";
  permissions?: string[];
  session?: boolean;
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

/** A session token (servers with sign-in, ADR 0012), or the legacy shared password. */
export interface ServerConfig {
  baseUrl: string;
  token?: string;
  password?: string;
}