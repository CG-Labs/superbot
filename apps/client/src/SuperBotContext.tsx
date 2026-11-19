import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { AppState as RNAppState } from "react-native";
import {
  clearCredentials,
  loadSavedCredentials,
  saveCredentials,
} from "./auth";
import { SuperBotApi } from "./api";
import {
  applyHandoffHistory,
  applyHandoffMessage,
  isHandoff,
  withoutHandoff,
  withPicked,
  type HandoffMap,
} from "./handoff";
import { createBody, patchBody, type RoutineDraft } from "./routines";
import { resolveScreenUrl } from "./screen";
import { connectSse } from "./sse";
import type { BotView, Message, ModelOption, Routine, SseEvent } from "./types";

interface SuperBotContextValue {
  ready: boolean;
  connected: boolean;
  error: string | null;
  api: SuperBotApi | null;
  me: { name: string };
  harnesses: string[];
  defaultHarness: string;
  bots: BotView[];
  activeId: string | null;
  setActiveId: (id: string | null) => void;
  messages: Record<string, Message[]>;
  drafts: Record<string, string>;
  /** botId -> the latest handoff card the user still has to act on. */
  handoffs: HandoffMap;
  modelCache: Record<string, ModelOption[]>;
  showHidden: boolean;
  setShowHidden: (v: boolean) => void;
  filter: string;
  setFilter: (v: string) => void;
  login: (baseUrl: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: (reloadMessages?: boolean) => Promise<void>;
  loadMessages: (botId: string) => Promise<void>;
  sendText: (text: string, answer?: { messageId: number; option: number }) => Promise<void>;
  /** Answers a choice or handoff card on the card's own Bot. Rejects (and undoes) on failure. */
  answerQuestion: (message: Message, option: number) => Promise<void>;
  createBot: (body: { name: string; color: string; shape: string; harness: string }) => Promise<BotView>;
  patchBot: (id: string, body: Record<string, unknown>) => Promise<void>;
  deleteBot: (id: string) => Promise<void>;
  stopBot: (id: string) => Promise<void>;
  fetchModels: (harness: string) => Promise<ModelOption[]>;
  fetchRoutines: (botId: string) => Promise<Routine[]>;
  toggleRoutine: (r: Routine) => Promise<void>;
  createRoutine: (botId: string, draft: RoutineDraft) => Promise<Routine>;
  updateRoutine: (r: Routine, draft: RoutineDraft) => Promise<Routine>;
  deleteRoutine: (id: string) => Promise<void>;
  /** Starts the Bot's screen; resolves to an absolute live-view link on this server. */
  fetchScreenUrl: (botId: string) => Promise<string>;
}

const SuperBotContext = createContext<SuperBotContextValue | null>(null);

export function useSuperBot(): SuperBotContextValue {
  const ctx = useContext(SuperBotContext);
  if (!ctx) throw new Error("useSuperBot outside provider");
  return ctx;
}

function upsertBot(list: BotView[], b: BotView): BotView[] {
  const i = list.findIndex((x) => x.id === b.id);
  if (i >= 0) {
    const next = [...list];
    next[i] = { ...next[i], ...b };
    return next;
  }
  return [...list, b];
}

export function SuperBotProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [api, setApi] = useState<SuperBotApi | null>(null);
  const [me, setMe] = useState({ name: "" });
  const [harnesses, setHarnesses] = useState<string[]>([]);
  const [defaultHarness, setDefaultHarness] = useState("claude");
  const [bots, setBots] = useState<BotView[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [handoffs, setHandoffs] = useState<HandoffMap>({});
  const [modelCache, setModelCache] = useState<Record<string, ModelOption[]>>({});
  const [showHidden, setShowHidden] = useState(false);
  const [filter, setFilter] = useState("");
  const sseRef = useRef<ReturnType<typeof connectSse> | null>(null);
  const openedRef = useRef(false);
  const messagesRef = useRef(messages);
  messagesRef.current = messages;

  const applyState = useCallback((state: Awaited<ReturnType<SuperBotApi["verify"]>>) => {
    setMe(state.me);
    setHarnesses(state.harnesses);
    setDefaultHarness(state.defaultHarness);
    setBots(state.bots);
    const primary = state.bots.find((b) => b.primary);
    setActiveId((cur) => (cur && state.bots.some((b) => b.id === cur) ? cur : primary?.id ?? null));
  }, []);

  const handleSse = useCallback(
    async (evt: SseEvent) => {
      if (evt.type === "resync") {
        if (api) void refreshInternal(api, true);
        return;
      }
      if (evt.type === "message") {
        // Only extend histories already loaded; an unloaded Bot loads its full history on open.
        setMessages((prev) => {
          const list = prev[evt.message.botId];
          if (!list || list.some((m) => m.id === evt.message.id)) return prev;
          return { ...prev, [evt.message.botId]: [...list, evt.message] };
        });
        setHandoffs((h) => applyHandoffMessage(h, evt.message));
        if (evt.message.role === "bot") {
          setDrafts((d) => {
            const next = { ...d };
            delete next[evt.message.botId];
            return next;
          });
        }
        if (evt.bot) setBots((bs) => upsertBot(bs, evt.bot as BotView));
        if (evt.message.botId === activeId && api) void api.markRead(evt.message.botId).catch(() => {});
      } else if (evt.type === "bot") {
        setBots((bs) => upsertBot(bs, evt.bot));
      } else if (evt.type === "botDeleted") {
        setBots((bs) => bs.filter((b) => b.id !== evt.botId));
        setHandoffs((h) => withoutHandoff(h, evt.botId));
        setActiveId((id) => {
          if (id !== evt.botId) return id;
          const primary = bots.find((b) => b.primary);
          return primary?.id ?? null;
        });
      } else if (evt.type === "draft") {
        setDrafts((d) => ({ ...d, [evt.botId]: evt.text }));
      } else if (evt.type === "status") {
        setBots((bs) =>
          bs.map((b) =>
            b.id === evt.botId ? { ...b, working: evt.working, status: evt.status } : b,
          ),
        );
        if (!evt.working) {
          setDrafts((d) => {
            const next = { ...d };
            delete next[evt.botId];
            return next;
          });
        }
      }
    },
    [activeId, api, bots],
  );
  const handleSseRef = useRef(handleSse);
  handleSseRef.current = handleSse;

  /** Loads unread Bots' chats in the background so their open handoffs show without opening each one. */
  const prefetchUnread = async (client: SuperBotApi, list: BotView[]) => {
    const ids = list.filter((b) => b.unread && !messagesRef.current[b.id]).map((b) => b.id);
    await Promise.all(
      ids.map(async (id) => {
        const history = await client.messages(id).catch(() => null);
        if (!history) return;
        setMessages((prev) => (prev[id] ? prev : { ...prev, [id]: history }));
        setHandoffs((h) => applyHandoffHistory(h, id, history));
      }),
    );
  };

  const refreshInternal = async (client: SuperBotApi, reloadMessages?: boolean) => {
    const state = await client.verify();
    applyState(state);
    void prefetchUnread(client, state.bots);
    if (reloadMessages) {
      const ids = Object.keys(messagesRef.current);
      const loaded: Record<string, Message[]> = {};
      for (const id of ids) {
        loaded[id] = await client.messages(id);
      }
      setMessages((prev) => ({ ...prev, ...loaded }));
      setHandoffs((h) => ids.reduce((acc, id) => applyHandoffHistory(acc, id, loaded[id]), h));
    }
  };

  const startSse = useCallback(
    (client: SuperBotApi) => {
      sseRef.current?.close();
      openedRef.current = false;
      sseRef.current = connectSse(
        client.eventsUrl(),
        client.authHeaders(),
        (ev) => void handleSseRef.current(ev),
        () => {
          if (openedRef.current) void refreshInternal(client, true);
          openedRef.current = true;
        },
        () => setConnected(false),
      );
      setConnected(true);
    },
    [],
  );

  const bootstrap = useCallback(
    async (client: SuperBotApi) => {
      setError(null);
      const state = await client.verify();
      applyState(state);
      setApi(client);
      startSse(client);
      void prefetchUnread(client, state.bots);
    },
    [applyState, startSse],
  );

  useEffect(() => {
    void (async () => {
      const saved = await loadSavedCredentials();
      if (saved?.password) {
        try {
          await bootstrap(new SuperBotApi(saved));
        } catch (err) {
          setError(err instanceof Error ? err.message : "Connection failed");
        }
      }
      setReady(true);
    })();
    return () => sseRef.current?.close();
  }, [bootstrap]);

  useEffect(() => {
    const sub = RNAppState.addEventListener("change", (s) => {
      if (s === "active" && activeId && api) void api.markRead(activeId).catch(() => {});
    });
    return () => sub.remove();
  }, [activeId, api]);

  const login = async (baseUrl: string, password: string) => {
    if (!password.trim()) throw new Error("Password is required");
    const client = new SuperBotApi({ baseUrl, password });
    await bootstrap(client);
    await saveCredentials(baseUrl, password);
  };

  const logout = async () => {
    sseRef.current?.close();
    setApi(null);
    setBots([]);
    setMessages({});
    setDrafts({});
    setHandoffs({});
    setConnected(false);
    await clearCredentials();
  };

  const refresh = async (reloadMessages?: boolean) => {
    if (!api) return;
    await refreshInternal(api, reloadMessages);
  };

  const loadMessages = async (botId: string) => {
    if (!api) return;
    if (!messagesRef.current[botId]) {
      const list = await api.messages(botId);
      setMessages((m) => ({ ...m, [botId]: list }));
      setHandoffs((h) => applyHandoffHistory(h, botId, list));
      void api.markRead(botId).catch(() => {});
    } else if (bots.find((b) => b.id === botId)?.unread) {
      // Prefetched in the background: opening it still marks it read.
      void api.markRead(botId).catch(() => {});
    }
  };

  const sendText = async (text: string, answer?: { messageId: number; option: number }) => {
    if (!api || !activeId || !text.trim()) return;
    await api.sendMessage(activeId, text.trim(), answer);
  };

  const answerQuestion = async (message: Message, option: number) => {
    const q = message.question;
    if (!api || !q || q.picked != null || option < 0 || option >= q.options.length) return;
    const setPicked = (picked: number | null) =>
      setMessages((prev) =>
        prev[message.botId] ? { ...prev, [message.botId]: withPicked(prev[message.botId], message.id, picked) } : prev,
      );
    setPicked(option);
    setHandoffs((h) => withoutHandoff(h, message.botId, message.id));
    try {
      await api.sendMessage(message.botId, q.options[option], { messageId: message.id, option });
    } catch (err) {
      setPicked(null);
      if (isHandoff(message)) setHandoffs((h) => (h[message.botId] ? h : { ...h, [message.botId]: message }));
      throw err;
    }
  };

  const createBot = async (body: { name: string; color: string; shape: string; harness: string }) => {
    if (!api) throw new Error("Not connected");
    const b = await api.createBot(body);
    setBots((bs) => upsertBot(bs, b));
    return b;
  };

  const patchBot = async (id: string, body: Record<string, unknown>) => {
    if (!api) return;
    const b = await api.patchBot(id, body);
    setBots((bs) => upsertBot(bs, b));
  };

  const deleteBot = async (id: string) => {
    if (!api) return;
    await api.deleteBot(id);
  };

  const stopBot = async (id: string) => {
    if (!api) return;
    await api.stopBot(id);
  };

  const fetchModels = async (harness: string) => {
    if (modelCache[harness]) return modelCache[harness];
    if (!api) return [];
    const list = await api.models(harness);
    setModelCache((c) => ({ ...c, [harness]: list }));
    return list;
  };

  const fetchRoutines = (botId: string) => {
    if (!api) return Promise.resolve([]);
    return api.routines(botId);
  };

  const toggleRoutine = async (r: Routine) => {
    if (!api) return;
    await api.patchRoutine(r.id, { enabled: !r.enabled });
  };

  const createRoutine = async (botId: string, draft: RoutineDraft) => {
    if (!api) throw new Error("Not connected");
    return api.createRoutine(botId, createBody(draft));
  };

  const updateRoutine = async (r: Routine, draft: RoutineDraft) => {
    if (!api) throw new Error("Not connected");
    const patch = patchBody(r, draft);
    if (!Object.keys(patch).length) return r;
    return api.patchRoutine(r.id, patch);
  };

  const deleteRoutine = async (id: string) => {
    if (!api) throw new Error("Not connected");
    await api.deleteRoutine(id);
  };

  const fetchScreenUrl = async (botId: string) => {
    if (!api) throw new Error("Not connected");
    const { url } = await api.screen(botId);
    return resolveScreenUrl(api.baseUrl, url);
  };

  const value = useMemo(
    () => ({
      ready,
      connected,
      error,
      api,
      me,
      harnesses,
      defaultHarness,
      bots,
      activeId,
      setActiveId,
      messages,
      drafts,
      handoffs,
      modelCache,
      showHidden,
      setShowHidden,
      filter,
      setFilter,
      login,
      logout,
      refresh,
      loadMessages,
      sendText,
      answerQuestion,
      createBot,
      patchBot,
      deleteBot,
      stopBot,
      fetchModels,
      fetchRoutines,
      toggleRoutine,
      createRoutine,
      updateRoutine,
      deleteRoutine,
      fetchScreenUrl,
    }),
    [
      ready,
      connected,
      error,
      api,
      me,
      harnesses,
      defaultHarness,
      bots,
      activeId,
      messages,
      drafts,
      handoffs,
      modelCache,
      showHidden,
      filter,
    ],
  );

  return <SuperBotContext.Provider value={value}>{children}</SuperBotContext.Provider>;
}