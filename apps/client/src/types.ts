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
  preview?: string;
  working: boolean;
  status?: string;
  draft?: string;
}

export interface ModelOption {
  id: string;
  label: string;
  efforts: string[];
  aliases?: string[];
}

export interface AppState {
  me: { name: string };
  harnesses: string[];
  defaultHarness: string;
  bots: BotView[];
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
  | { type: "resync" };

export interface ServerConfig {
  baseUrl: string;
  password: string;
}