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
import { connectSse } from "./sse";
import type { Approval, BotView, Message, ModelOption, Policy, PolicyMode, Routine, SseEvent } from "./types";

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
  createBot: (body: { name: string; color: string; shape: string; harness: string }) => Promise<BotView>;
  patchBot: (id: string, body: Record<string, unknown>) => Promise<void>;
  deleteBot: (id: string) => Promise<void>;
  stopBot: (id: string) => Promise<void>;
  fetchModels: (harness: string) => Promise<ModelOption[]>;
  fetchRoutines: (botId: string) => Promise<Routine[]>;
  toggleRoutine: (r: Routine) => Promise<void>;
  /** Pending approvals, oldest first. */
  approvals: Approval[];
  policy: Policy | null;
  decideApproval: (id: string, approve: boolean, remember: boolean) => Promise<void>;
  setGlobalPolicy: (mode: PolicyMode) => Promise<void>;
  setBotPolicy: (botId: string, mode: PolicyMode | null) => Promise<void>;
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

function upsertApproval(list: Approval[], a: Approval): Approval[] {
  const rest = list.filter((x) => x.id !== a.id);
  return a.status === "pending" ? [...rest, a].sort((x, y) => x.createdAt - y.createdAt) : rest;
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
  const [modelCache, setModelCache] = useState<Record<string, ModelOption[]>>({});
  const [showHidden, setShowHidden] = useState(false);
  const [filter, setFilter] = useState("");
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const sseRef = useRef<ReturnType<typeof connectSse> | null>(null);
  const openedRef = useRef(false);

  const applyState = useCallback((state: Awaited<ReturnType<SuperBotApi["verify"]>>) => {
    setMe(state.me);
    setHarnesses(state.harnesses);
    setDefaultHarness(state.defaultHarness);
    setBots(state.bots);
    setApprovals((state.approvals ?? []).reduce(upsertApproval, []));
    setPolicy(state.policy ?? null);
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
        setMessages((prev) => {
          const list = prev[evt.message.botId] ?? [];
          if (list.some((m) => m.id === evt.message.id)) return prev;
          return { ...prev, [evt.message.botId]: [...list, evt.message] };
        });
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
        setActiveId((id) => {
          if (id !== evt.botId) return id;
          const primary = bots.find((b) => b.primary);
          return primary?.id ?? null;
        });
      } else if (evt.type === "draft") {
        setDrafts((d) => ({ ...d, [evt.botId]: evt.text }));
      } else if (evt.type === "approval") {
        setApprovals((list) => upsertApproval(list, evt.approval));
      } else if (evt.type === "policy") {
        setPolicy(evt.policy);
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

  const refreshInternal = async (client: SuperBotApi, reloadMessages?: boolean) => {
    const state = await client.verify();
    applyState(state);
    if (reloadMessages) {
      const ids = Object.keys(messages);
      const loaded: Record<string, Message[]> = { ...messages };
      for (const id of ids) {
        loaded[id] = await client.messages(id);
      }
      setMessages(loaded);
    }
  };

  const startSse = useCallback(
    (client: SuperBotApi) => {
      sseRef.current?.close();
      openedRef.current = false;
      sseRef.current = connectSse(
        client.eventsUrl(),
        client.authHeaders(),
        (ev) => void handleSse(ev),
        () => {
          if (openedRef.current) void refreshInternal(client, true);
          openedRef.current = true;
        },
        () => setConnected(false),
      );
      setConnected(true);
    },
    [handleSse],
  );

  const bootstrap = useCallback(
    async (client: SuperBotApi) => {
      setError(null);
      const state = await client.verify();
      applyState(state);
      setApi(client);
      startSse(client);
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
    setApprovals([]);
    setConnected(false);
    await clearCredentials();
  };

  const refresh = async (reloadMessages?: boolean) => {
    if (!api) return;
    await refreshInternal(api, reloadMessages);
  };

  const loadMessages = async (botId: string) => {
    if (!api || messages[botId]) return;
    const list = await api.messages(botId);
    setMessages((m) => ({ ...m, [botId]: list }));
    void api.markRead(botId).catch(() => {});
  };

  const sendText = async (text: string, answer?: { messageId: number; option: number }) => {
    if (!api || !activeId || !text.trim()) return;
    await api.sendMessage(activeId, text.trim(), answer);
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

  const decideApproval = async (id: string, approve: boolean, remember: boolean) => {
    if (!api) return;
    const a = await api.decideApproval(id, approve, remember);
    setApprovals((list) => upsertApproval(list, a));
  };

  const setGlobalPolicy = async (mode: PolicyMode) => {
    if (!api) return;
    setPolicy(await api.setGlobalPolicy(mode));
  };

  const setBotPolicy = async (botId: string, mode: PolicyMode | null) => {
    if (!api) return;
    await api.setBotPolicy(botId, mode);
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
      createBot,
      patchBot,
      deleteBot,
      stopBot,
      fetchModels,
      fetchRoutines,
      toggleRoutine,
      approvals,
      policy,
      decideApproval,
      setGlobalPolicy,
      setBotPolicy,
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
      modelCache,
      showHidden,
      filter,
      approvals,
      policy,
    ],
  );

  return <SuperBotContext.Provider value={value}>{children}</SuperBotContext.Provider>;
}