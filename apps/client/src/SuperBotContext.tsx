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
import { hasAccess } from "./access";
import { ApiError, signIn, SuperBotApi } from "./api";
import {
  applyHandoffHistory,
  applyHandoffMessage,
  isHandoff,
  withoutHandoff,
  withPicked,
  type HandoffMap,
} from "./handoff";
import { takeInviteCode } from "./invite";
import { createBody, patchBody, type RoutineDraft } from "./routines";
import { signInWithSso } from "./sso";
import { resolveScreenUrl } from "./screen";
import { connectSse } from "./sse";
import type {
  Approval,
  BotAccess,
  BotView,
  Me,
  Message,
  ModelOption,
  Policy,
  PolicyMode,
  Routine,
  SseEvent,
  Visibility,
} from "./types";

interface SuperBotContextValue {
  ready: boolean;
  connected: boolean;
  error: string | null;
  api: SuperBotApi | null;
  me: Me;
  /** Whether this person's role may change things. The server enforces it; this hides what would fail. */
  canWrite: boolean;
  /** Whether the server lets this person do `perm` (see ADR 0012). */
  can: (perm: string) => boolean;
  /** Whether this person may do what takes `need` on the Bot (ADR 0017): view, operate (run it), or manage. */
  canOnBot: (bot: BotView | null | undefined, need: BotAccess) => boolean;
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
  /** A sign-in code from an invite link this page was opened with, to fill in (ADR 0021). */
  inviteCode: string | null;
  /** Keeps a code taken from the address bar, so it outlives the page that found it. */
  offerInviteCode: (code: string) => void;
  /** `secret` is a one-time sign-in code, or the server password (break-glass). */
  login: (baseUrl: string, secret: string) => Promise<void>;
  /** Signs in through one of the server's SSO providers, in the system browser. */
  loginWithSso: (baseUrl: string, providerId: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: (reloadMessages?: boolean) => Promise<void>;
  loadMessages: (botId: string) => Promise<void>;
  sendText: (text: string, answer?: { messageId: number; option: number }) => Promise<void>;
  /** Answers a choice or handoff card on the card's own Bot. Rejects (and undoes) on failure. */
  answerQuestion: (message: Message, option: number) => Promise<void>;
  createBot: (body: { name: string; color: string; shape: string; harness: string }) => Promise<BotView>;
  patchBot: (id: string, body: Record<string, unknown>) => Promise<void>;
  /** Shares the Bot with everyone, or makes it private to its owner and grants. */
  setBotVisibility: (id: string, visibility: Visibility) => Promise<void>;
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

function mergeMessages(base: Message[], extra: Message[]): Message[] {
  const seen = new Set(base.map((m) => m.id));
  const added = extra.filter((m) => !seen.has(m.id));
  return added.length ? [...base, ...added].sort((a, b) => a.id - b.id) : base;
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
  const [inviteCode, offerInviteCode] = useState(() => takeInviteCode());
  const [me, setMe] = useState<Me>({ name: "" });
  // Servers from before roles send no permissions; everyone could write there.
  const can = (perm: string) => !me.permissions || me.permissions.includes(perm);
  const canWrite = can("write");
  const canOnBot = (bot: BotView | null | undefined, need: BotAccess) => hasAccess(bot, need, canWrite);
  const canWriteRef = useRef(canWrite);
  canWriteRef.current = canWrite;
  const [harnesses, setHarnesses] = useState<string[]>([]);
  const [defaultHarness, setDefaultHarness] = useState("claude");
  const [bots, setBots] = useState<BotView[]>([]);
  const botsRef = useRef(bots);
  botsRef.current = bots;
  // Marking read changes the Bot for everyone, so it takes operator access to it.
  const markRead = (client: SuperBotApi, botId: string) => {
    const bot = botsRef.current.find((b) => b.id === botId);
    if (hasAccess(bot, "operate", canWriteRef.current)) void client.markRead(botId).catch(() => {});
  };
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [handoffs, setHandoffs] = useState<HandoffMap>({});
  const [modelCache, setModelCache] = useState<Record<string, ModelOption[]>>({});
  const [showHidden, setShowHidden] = useState(false);
  const [filter, setFilter] = useState("");
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const sseRef = useRef<ReturnType<typeof connectSse> | null>(null);
  const clientRef = useRef<SuperBotApi | null>(null);
  const openedRef = useRef(false);
  const messagesRef = useRef(messages);
  messagesRef.current = messages;
  /** Live messages that arrived while a Bot's history was loading; the server's snapshot may predate them. */
  const liveRef = useRef<Record<string, { waiting: number; list: Message[] }>>({});

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
        liveRef.current[evt.message.botId]?.list.push(evt.message);
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
        if (evt.message.botId === activeId && api) markRead(api, evt.message.botId);
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
  const handleSseRef = useRef(handleSse);
  handleSseRef.current = handleSse;

  const fetchHistory = async (client: SuperBotApi, botId: string) => {
    const entry = (liveRef.current[botId] ??= { waiting: 0, list: [] });
    entry.waiting++;
    try {
      return mergeMessages(await client.messages(botId), entry.list);
    } finally {
      if (--entry.waiting === 0 && liveRef.current[botId] === entry) delete liveRef.current[botId];
    }
  };

  /** Loads unread or waiting Bots' chats in the background so their open handoffs show without opening each one. */
  const prefetchUnread = async (client: SuperBotApi, list: BotView[]) => {
    const ids = list.filter((b) => (b.unread || b.handoff != null) && !messagesRef.current[b.id]).map((b) => b.id);
    await Promise.all(
      ids.map(async (id) => {
        const history = await fetchHistory(client, id).catch(() => null);
        if (!history) return;
        setMessages((prev) => (prev[id] ? prev : { ...prev, [id]: history }));
        setHandoffs((h) => applyHandoffHistory(h, id, history));
      }),
    );
  };

  const refreshInternal = async (client: SuperBotApi, reloadMessages?: boolean) => {
    const state = await client.verify();
    applyState(state);
    // Drop what's cached for Bots this person can no longer see (access was revoked).
    const visible = new Set(state.bots.map((b) => b.id));
    const drop = <T,>(map: Record<string, T>) => {
      if (!Object.keys(map).some((id) => !visible.has(id))) return map;
      return Object.fromEntries(Object.entries(map).filter(([id]) => visible.has(id)));
    };
    setMessages(drop);
    setDrafts(drop);
    setHandoffs(drop);
    void prefetchUnread(client, state.bots);
    if (reloadMessages) {
      for (const id of Object.keys(messagesRef.current)) {
        if (!visible.has(id)) continue;
        // One chat failing to load mustn't stop the rest from catching up.
        const list = await fetchHistory(client, id).catch(() => null);
        if (!list) continue;
        setMessages((prev) => ({ ...prev, [id]: list }));
        setHandoffs((h) => applyHandoffHistory(h, id, list));
      }
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
        () => {
          setConnected(false);
          // A revoked session closes the stream; a quick request tells that apart from a network drop.
          if (client.config.token) void client.verify().catch(() => {});
        },
      );
      setConnected(true);
    },
    [],
  );

  const reset = () => {
    sseRef.current?.close();
    clientRef.current = null;
    setApi(null);
    offerInviteCode(null);
    setBots([]);
    setMessages({});
    setDrafts({});
    setHandoffs({});
    setApprovals([]);
    setConnected(false);
  };
  const resetRef = useRef(reset);
  resetRef.current = reset;

  const bootstrap = useCallback(
    async (client: SuperBotApi) => {
      setError(null);
      client.onSessionEnded = () => {
        if (clientRef.current !== client) return;
        resetRef.current();
        void clearCredentials();
        setError("Your session ended. Sign in again.");
      };
      const state = await client.verify();
      applyState(state);
      clientRef.current = client;
      setApi(client);
      // Signed in: an invite code from the link is spent, or wasn't needed.
      offerInviteCode(null);
      startSse(client);
      void prefetchUnread(client, state.bots);
    },
    [applyState, startSse],
  );

  useEffect(() => {
    void (async () => {
      let saved = await loadSavedCredentials();
      // A password saved before sign-in existed is swapped for a session token, once.
      if (saved?.password && !saved.token) {
        const upgraded = await signIn(saved.baseUrl, saved.password).catch(() => null);
        if (upgraded?.token) {
          saved = upgraded;
          await saveCredentials(upgraded);
        }
      }
      if (saved?.token || saved?.password) {
        try {
          await bootstrap(new SuperBotApi(saved));
        } catch (err) {
          if (err instanceof ApiError && err.status === 401 && saved.token) {
            await clearCredentials();
            setError("Your session ended. Sign in again.");
          } else {
            setError(err instanceof Error ? err.message : "Connection failed");
          }
        }
      }
      setReady(true);
    })();
    return () => sseRef.current?.close();
  }, [bootstrap]);

  useEffect(() => {
    const sub = RNAppState.addEventListener("change", (s) => {
      if (s === "active" && activeId && api) markRead(api, activeId);
    });
    return () => sub.remove();
  }, [activeId, api]);

  const login = async (baseUrl: string, secret: string) => {
    if (!secret.trim()) throw new Error("A sign-in code or password is required");
    const cfg = await signIn(baseUrl, secret.trim());
    const client = new SuperBotApi(cfg);
    await bootstrap(client);
    await saveCredentials(cfg);
  };

  const loginWithSso = async (baseUrl: string, providerId: string) => {
    const cfg = await signInWithSso(baseUrl, providerId);
    await bootstrap(new SuperBotApi(cfg));
    await saveCredentials(cfg);
  };

  // Signs out on the device first, so a slow server can't keep anyone signed in.
  const logout = async () => {
    const client = api;
    reset();
    await clearCredentials();
    void client?.logout().catch(() => {});
  };

  const refresh = async (reloadMessages?: boolean) => {
    if (!api) return;
    await refreshInternal(api, reloadMessages);
  };

  const loadMessages = async (botId: string) => {
    if (!api) return;
    if (!messagesRef.current[botId]) {
      const list = await fetchHistory(api, botId);
      setMessages((m) => ({ ...m, [botId]: list }));
      setHandoffs((h) => applyHandoffHistory(h, botId, list));
      markRead(api, botId);
    } else if (bots.find((b) => b.id === botId)?.unread) {
      // Prefetched in the background: opening it still marks it read.
      markRead(api, botId);
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

  const setBotVisibility = async (id: string, visibility: Visibility) => {
    if (!api) return;
    const res = await api.patchBotAccess(id, { visibility });
    setBots((bs) => bs.map((b) => (b.id === id ? { ...b, visibility: res.visibility, access: res.access } : b)));
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
      canWrite,
      can,
      canOnBot,
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
      inviteCode,
      offerInviteCode,
      login,
      loginWithSso,
      logout,
      refresh,
      loadMessages,
      sendText,
      answerQuestion,
      createBot,
      patchBot,
      setBotVisibility,
      deleteBot,
      stopBot,
      fetchModels,
      fetchRoutines,
      toggleRoutine,
      createRoutine,
      updateRoutine,
      deleteRoutine,
      fetchScreenUrl,
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
      handoffs,
      modelCache,
      showHidden,
      filter,
      approvals,
      policy,
      inviteCode,
    ],
  );

  return <SuperBotContext.Provider value={value}>{children}</SuperBotContext.Provider>;
}