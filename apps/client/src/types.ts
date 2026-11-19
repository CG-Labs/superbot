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