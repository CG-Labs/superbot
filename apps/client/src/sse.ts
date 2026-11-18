import { Platform } from "react-native";
import EventSource from "react-native-sse";
import type { SseEvent } from "./types";

type Listener = (event: SseEvent) => void;

/** Parse one SSE stream from a fetch body (web / Electron). */
async function readFetchSse(
  url: string,
  headers: Record<string, string>,
  onEvent: Listener,
  signal: AbortSignal,
): Promise<void> {
  const res = await fetch(url, { headers, signal });
  if (!res.ok || !res.body) {
    throw new Error(`SSE failed: HTTP ${res.status}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (!signal.aborted) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buffer.indexOf("\n\n")) >= 0) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const dataLine = chunk.split("\n").find((l) => l.startsWith("data:"));
      if (!dataLine) continue;
      const data = dataLine.slice(5).trim();
      if (!data) continue;
      try {
        onEvent(JSON.parse(data) as SseEvent);
      } catch {
        /* ignore malformed */
      }
    }
  }
}

export type SseConnection = { close: () => void };

export function connectSse(
  url: string,
  headers: Record<string, string>,
  onEvent: Listener,
  onOpen?: () => void,
  onError?: (err: unknown) => void,
): SseConnection {
  if (Platform.OS === "web") {
    const controller = new AbortController();
    let opened = false;
    void (async () => {
      while (!controller.signal.aborted) {
        try {
          await readFetchSse(url, headers, onEvent, controller.signal);
        } catch (err) {
          if (!controller.signal.aborted) onError?.(err);
        }
        if (controller.signal.aborted) break;
        if (!opened) {
          opened = true;
          onOpen?.();
        } else {
          onOpen?.();
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
    })();
    return { close: () => controller.abort() };
  }

  const es = new EventSource(url, { headers, pollingInterval: 0, timeout: 0 });
  es.addEventListener("open", () => onOpen?.());
  es.addEventListener("message", (ev) => {
    if (!ev.data) return;
    try {
      onEvent(JSON.parse(ev.data) as SseEvent);
    } catch {
      /* ignore */
    }
  });
  es.addEventListener("error", (err) => onError?.(err));
  return { close: () => es.close() };
}