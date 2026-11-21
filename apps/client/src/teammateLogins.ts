import type { LoginEvent, TeammateHarnessLogin } from "./types";

/**
 * Your own harness logins on a teammate's computer (ADR 0062), or on this server for their
 * Bots (ADR 0064): when you run their shared Bot, Claude Code or Codex uses your account,
 * never theirs. The same path serves both; the server picks.
 */
export function teammateLoginPath(ownerId: string, rest: string): string {
  return `/api/machine/teammate/${encodeURIComponent(ownerId)}/${rest}`;
}

/** Splits a growing body of JSON lines into the events not read yet. */
export class LineReader {
  private at = 0;

  /** `text` is the whole body so far. */
  read(text: string): LoginEvent[] {
    const out: LoginEvent[] = [];
    for (;;) {
      const nl = text.indexOf("\n", this.at);
      if (nl < 0) return out;
      const line = text.slice(this.at, nl).trim();
      this.at = nl + 1;
      if (!line) continue;
      try {
        out.push(JSON.parse(line) as LoginEvent);
      } catch {
        // Not an event: skip it rather than end the login.
      }
    }
  }
}

const TERMINAL_CODES = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)|\u001b[@-Z\\-_]|\r/g;

/** What a terminal shows, without its colors and cursor moves. */
export function plainOutput(text: string): string {
  return text.replace(TERMINAL_CODES, "");
}

/** The last link a login showed, to open in a browser. */
export function lastLink(text: string): string | null {
  const all = plainOutput(text).match(/https:\/\/[^\s"'<>]+/g);
  return all ? all[all.length - 1] : null;
}

/** What a harness's login state means for your runs of the owner's Bots: on their
 *  computer, or on this server as your own account for their Bots (ADR 0064). */
export function loginLine(h: TeammateHarnessLogin | undefined, owner: string, on: "machine" | "server" = "machine"): string {
  const where = on === "server" ? `for ${owner}'s Bots on this server` : `on ${owner}'s computer`;
  if (h?.state === "logged_in") return `Logged in with your own account ${where}.`;
  if (h?.state === "logging_in") return "A login is running.";
  if (h?.serverKey) return `Not logged in. A server-wide key runs it for you ${where}.`;
  return `Not logged in. Your runs ${where} are refused until you log in. ${owner}'s login is never used for you.`;
}

/** The parts of XMLHttpRequest a login stream uses, so tests can stand in for it. */
export interface StreamXhr {
  open(method: string, url: string): void;
  setRequestHeader(name: string, value: string): void;
  send(body: string): void;
  abort(): void;
  readonly responseText: string;
  readonly status: number;
  onprogress: (() => void) | null;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  onabort: (() => void) | null;
}

export interface LoginStream {
  /** Stops reading; the server then stops the login. */
  stop: () => void;
  /** Settles when the stream ends: rejects if the server refused or the connection dropped. */
  done: Promise<void>;
}

/** An error the server gave, with its HTTP status. */
export class LoginError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "LoginError";
  }
}

/**
 * Starts a login and hands each event to `onEvent` as it comes. XMLHttpRequest rather
 * than fetch: React Native's fetch doesn't stream a response body; both platforms report
 * an XMLHttpRequest's body as it grows.
 */
export function streamLogin(
  make: () => StreamXhr,
  url: string,
  headers: Record<string, string>,
  harness: string,
  onEvent: (e: LoginEvent) => void,
): LoginStream {
  const xhr = make();
  const reader = new LineReader();
  const drain = () => {
    for (const e of reader.read(xhr.responseText ?? "")) onEvent(e);
  };
  const done = new Promise<void>((resolve, reject) => {
    xhr.onprogress = () => {
      if (xhr.status >= 200 && xhr.status < 300) drain();
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        drain();
        resolve();
        return;
      }
      let message = `HTTP ${xhr.status}`;
      try {
        message = (JSON.parse(xhr.responseText) as { error?: string }).error ?? message;
      } catch {
        // Not JSON: keep the status.
      }
      reject(new LoginError(message, xhr.status));
    };
    xhr.onerror = () => reject(new LoginError("The connection to the server dropped.", 0));
    xhr.onabort = () => resolve();
  });
  xhr.open("POST", url);
  for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value);
  xhr.send(JSON.stringify({ harness }));
  return { stop: () => xhr.abort(), done };
}
