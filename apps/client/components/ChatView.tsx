import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  FlatList,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputInstance,
} from "react-native";
import { useAnnounce } from "../src/announce";
import { copyText, COPY_LABEL } from "../src/clipboard";
import { friendlyError } from "../src/errors";
import { isOpenHandoff } from "../src/handoff";
import { useReducedMotion } from "../src/motion";
import { isQueued, workingLabel } from "../src/runQueue";
import { useSuperBot } from "../src/SuperBotContext";
import { HARNESS_NAMES, hairline, themedStyles, type, useTheme } from "../src/theme";
import type { Message } from "../src/types";
import { unsentFor, type Unsent } from "../src/unsent";
import { ApprovalCard } from "./ApprovalsInbox";
import { BotAvatar } from "./BotAvatar";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { HandoffBanner } from "./HandoffBanner";
import { Markdown } from "./Markdown";
import { ModelBar, PlanBar } from "./ModelBar";
import { ChatSkeleton, ThinkingDots } from "./Skeleton";
import { useToast } from "./Toast";

/** Glyph buttons keep their size at large text settings; their names are read out instead. */
const GLYPH_SCALE = 1.3;

interface Props {
  onOpenDetails: () => void;
  /** Opens the new-Bot form, offered when there are no Bots yet. */
  onNewBot?: () => void;
  onBack?: () => void;
  /** Opens the Bot's live screen; `takeOver` starts with control (from a handoff). */
  onToggleScreen: (takeOver?: boolean) => void;
  screenOpen?: boolean;
  /** Text to put in the message box, e.g. a suggested starter (ADR 0054). */
  prefill?: string | null;
  /** Called once `prefill` is in the box, so it isn't put there again. */
  onPrefilled?: () => void;
}

/** Who a Bot-to-Bot message came from. */
export function peerLabel(m: Message, bots: { id: string; name: string }[]): string {
  const who = bots.find((b) => b.id === m.fromBot)?.name ?? "another Bot";
  return m.role === "peer" ? `From ${who}` : `Reply from ${who}`;
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function ChatView({ onOpenDetails, onNewBot, onBack, onToggleScreen, screenOpen, prefill, onPrefilled }: Props) {
  const {
    api,
    bots,
    activeId,
    messages,
    drafts,
    handoffs,
    loadMessages,
    sendText,
    answerQuestion,
    stopBot,
    approvals,
    canWrite,
    canOnBot,
    me,
  } = useSuperBot();
  const t = useTheme();
  const styles = useStyles();
  const toast = useToast();
  const reduceMotion = useReducedMotion();
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [composing, setComposing] = useState(false);
  const listRef = useRef<FlatList>(null);
  const inputRef = useRef<TextInputInstance>(null);
  const loadRef = useRef(loadMessages);
  loadRef.current = loadMessages;

  const bot = bots.find((b) => b.id === activeId);
  const canOperate = canOnBot(bot, "operate");
  const avatarEdge = t.scheme === "light" ? t.c.borderStrong : undefined;

  /** Loads the open chat's history; a load for a Bot that's no longer open is dropped. */
  const shownRef = useRef(activeId);
  shownRef.current = activeId;
  const load = useCallback(async (id: string) => {
    setLoading(true);
    setLoadError(null);
    try {
      await loadRef.current(id);
    } catch (err) {
      if (shownRef.current === id) setLoadError(friendlyError(err));
    } finally {
      if (shownRef.current === id) setLoading(false);
    }
  }, []);

  const textRef = useRef(text);
  textRef.current = text;
  const unsent = unsentFor(api);
  const unsentRef = useRef(unsent);
  unsentRef.current = unsent;
  const toastRef = useRef(toast);
  toastRef.current = toast;
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  /** The Bot whose failed send is back in the box, until the box is emptied. */
  const restoredRef = useRef<string | null>(null);
  /** Saves the box's failed words with their Bot again before they leave it. */
  const keepRestored = (id: string, store: Unsent) => {
    if (restoredRef.current !== id) return;
    restoredRef.current = null;
    const words = textRef.current;
    if (!words || store.ended) return;
    const saved = store.words[id];
    store.words[id] = saved && saved !== words ? `${words}\n\n${saved}` : words;
  };
  const keepRef = useRef(keepRestored);
  keepRef.current = keepRestored;
  const edit = (value: string) => {
    if (!value) restoredRef.current = null;
    setText(value);
  };

  useEffect(() => {
    if (!activeId) return;
    // Only into an empty box; otherwise it waits for the next visit or a Retry.
    const store = unsentRef.current;
    const saved = store.words[activeId];
    if (saved && !textRef.current) {
      delete store.words[activeId];
      restoredRef.current = activeId;
      textRef.current = saved;
      setText(saved);
      // Back in the box, the words are sent from there; a Retry could send them twice.
      const retry = store.retries[activeId];
      if (retry?.body === saved) {
        delete store.retries[activeId];
        toastRef.current.dismiss(retry.toast);
      }
    }
    void load(activeId);
    // Closing the chat or opening another Bot takes the words back, so they're neither lost nor sent to the wrong Bot.
    return () => {
      if (restoredRef.current !== activeId) return;
      keepRef.current(activeId, store);
      textRef.current = "";
      setText("");
    };
  }, [activeId, load]);

  useEffect(() => {
    if (prefill == null) return;
    if (activeId) keepRestored(activeId, unsent);
    setText(prefill);
    inputRef.current?.focus();
    onPrefilled?.();
    // onPrefilled is a new function on every parent render; only a new prefill matters.
  }, [prefill]);

  const working = bot?.working ? `${workingLabel(bot)}…` : null;
  useAnnounce(working);

  if (!bot) {
    return (
      <View style={styles.empty}>
        {bots.length ? (
          <EmptyState glyph="☰" title="Pick a bot to start chatting" message="Your Bots are in the list. Each one has its own computer to work on." />
        ) : (
          <EmptyState
            glyph="+"
            title="No Bots yet"
            message={
              canWrite && onNewBot
                ? "Make your first Bot to start chatting. Each one has its own computer to work on."
                : "Bots shared with you show up here."
            }
            action={canWrite && onNewBot ? { label: "New Bot", onPress: onNewBot } : undefined}
          />
        )}
      </View>
    );
  }

  const list = messages[bot.id] || [];
  const draft = drafts[bot.id];
  const handoff = handoffs[bot.id];
  const hasText = text.trim().length > 0;

  const answer = (m: Message, option: number) =>
    void answerQuestion(m, option).catch((err) => toast.error(err, "Couldn't send your answer"));

  const send = (body: string, id: string, store = unsent) =>
    void sendText(body, undefined, id).catch((err) => {
      if (store.ended) return;
      // Gives the words back unless something new was typed meanwhile.
      if (!mountedRef.current || shownRef.current !== id) store.words[id] = body;
      else
        setText((cur) => {
          if (!cur) {
            restoredRef.current = id;
            return body;
          }
          store.words[id] = body;
          return cur;
        });
      const retry = { body, toast: 0 };
      store.retries[id] = retry;
      retry.toast = toast.error(err, "Couldn't send your message", {
        label: "Retry",
        onPress: () => {
          if (store.ended || store.retries[id] !== retry) return;
          delete store.retries[id];
          if (mountedRef.current && shownRef.current === id)
            setText((cur) => {
              if (cur !== body) return cur;
              restoredRef.current = null;
              return "";
            });
          if (store.words[id] === body) delete store.words[id];
          send(body, id, store);
        },
      });
    });

  const onSend = () => {
    const body = text.trim();
    if (!body) return;
    const retry = unsent.retries[bot.id];
    if (retry?.body === body) {
      delete unsent.retries[bot.id];
      toast.dismiss(retry.toast);
    }
    if (unsent.words[bot.id] === body) delete unsent.words[bot.id];
    restoredRef.current = null;
    setText("");
    send(body, bot.id);
  };

  const stop = () => void stopBot(bot.id).catch((err) => toast.error(err, isQueued(bot) ? "Couldn't cancel it" : "Couldn't stop it"));

  const renderItem = ({ item, index }: { item: Message; index: number }) => {
    const prev = list[index - 1];
    const gap = !prev || item.at - prev.at > 30 * 60000;
    const isUser = item.role === "user";
    return (
      <View>
        {gap ? <Text style={styles.ts}>{formatTime(item.at)}</Text> : null}
        {item.role === "routine" ? (
          <View style={styles.routineRow}>
            <Text style={styles.routine}>Routine · {item.text}</Text>
          </View>
        ) : (
          <View style={[styles.row, isUser && styles.rowUser]}>
            <View style={[isUser ? styles.bubbleUser : styles.reply, item.error && styles.bubbleError]}>
              {item.role === "peer" || item.role === "reply" ? (
                <Text style={styles.from}>{peerLabel(item, bots)}</Text>
              ) : null}
              {isUser ? (
                <Text style={styles.userText}>{item.text}</Text>
              ) : (
                <Markdown>{item.text}</Markdown>
              )}
              {!isUser && item.text ? (
                <Pressable
                  role="button"
                  aria-label={`${COPY_LABEL} message`}
                  style={({ pressed }) => [styles.copy, pressed && styles.pressed]}
                  onPress={() => void copyText(item.text)}
                >
                  <Text style={styles.copyText}>{COPY_LABEL}</Text>
                </Pressable>
              ) : null}
              {item.question ? (
                <View style={styles.question}>
                  <Text style={styles.qTitle}>{item.question.title}</Text>
                  {canOperate && isOpenHandoff(item) ? (
                    <Pressable
                      role="button"
                      aria-label="Open screen"
                      style={({ pressed }) => [styles.openScreen, pressed && styles.pressed]}
                      onPress={() => onToggleScreen(true)}
                    >
                      <Text style={styles.openScreenText}>Open screen</Text>
                    </Pressable>
                  ) : null}
                  {item.question.options.map((opt, k) => (
                    <Pressable
                      key={k}
                      role="button"
                      aria-label={opt}
                      aria-selected={item.question?.picked === k}
                      aria-disabled={!canOperate || item.question?.picked != null}
                      style={({ pressed }) => [styles.opt, item.question?.picked === k && styles.optOn, pressed && styles.optPressed]}
                      disabled={!canOperate || item.question?.picked != null}
                      onPress={() => answer(item, k)}
                    >
                      <Text style={styles.optText}>{opt}</Text>
                    </Pressable>
                  ))}
                </View>
              ) : null}
            </View>
          </View>
        )}
      </View>
    );
  };

  const footer = (
    <View>
      {approvals
        .filter((a) => a.botId === bot.id)
        .map((a) => (
          <View key={a.id} style={styles.row}>
            <ApprovalCard approval={a} />
          </View>
        ))}
      {draft ? (
        <View style={styles.row}>
          <View style={styles.reply}>
            <Markdown>{draft}</Markdown>
          </View>
        </View>
      ) : null}
      {bot.working ? (
        <View style={styles.working}>
          <ThinkingDots />
          <Text style={styles.workingText} aria-live="polite">
            {working}
          </Text>
          {canOperate ? (
            <Pressable
              role="button"
              aria-label={isQueued(bot) ? `Cancel ${bot.name}'s queued run` : `Stop ${bot.name}`}
              style={({ pressed }) => [styles.stopBtn, pressed && styles.pressed]}
              onPress={stop}
            >
              <Text style={styles.stop}>{isQueued(bot) ? "Cancel" : "Stop"}</Text>
            </Pressable>
          ) : null}
        </View>
      ) : null}
    </View>
  );

  const welcome =
    !draft && !bot.working ? (
      <EmptyState
        art={<BotAvatar color={bot.color} shape={bot.shape} size={64} outline={avatarEdge} />}
        title={`Say hello to ${bot.name}`}
        message={
          canOperate ? `Ask ${bot.name} anything. It works on its own computer and tells you when it needs you.` : `${bot.name} hasn't said anything yet.`
        }
      />
    ) : null;

  const harnessName = HARNESS_NAMES[bot.harness] ?? bot.harness;

  return (
    <View style={styles.chat}>
      <View style={styles.header}>
        {onBack ? (
          <Pressable onPress={onBack} style={({ pressed }) => [styles.backBtn, pressed && styles.pressed]} role="button" aria-label="Back to Bots">
            <Text style={styles.backText} maxFontSizeMultiplier={GLYPH_SCALE}>
              ‹
            </Text>
          </Pressable>
        ) : null}
        <Pressable
          role="button"
          aria-label={`${bot.name}, ${harnessName}`}
          accessibilityHint="Opens the Bot's details"
          style={({ pressed }) => [styles.pill, pressed && styles.pressed]}
          onPress={onOpenDetails}
        >
          <BotAvatar color={bot.color} shape={bot.shape} size={30} outline={avatarEdge} />
          <Text style={styles.pillName} numberOfLines={1}>
            {bot.name}
          </Text>
          <View style={styles.harnessChip}>
            <Text style={styles.harness}>{harnessName}</Text>
          </View>
        </Pressable>
        {canOperate ? (
          <Pressable
            role="button"
            aria-label={screenOpen ? "Hide screen" : "Show screen"}
            aria-pressed={!!screenOpen}
            style={({ pressed }) => [styles.screenBtn, screenOpen && styles.screenBtnOn, pressed && styles.pressed]}
            onPress={() => onToggleScreen()}
          >
            <Text style={[styles.screenBtnText, screenOpen && styles.screenBtnTextOn]}>Screen</Text>
          </Pressable>
        ) : null}
      </View>
      {handoff ? (
        <View style={styles.column}>
          <HandoffBanner botName={bot.name} handoff={handoff} onOpenScreen={() => onToggleScreen(true)} />
        </View>
      ) : null}
      {loadError && !messages[bot.id] ? (
        <ErrorState title="Couldn't load this chat" message={loadError} onRetry={() => load(bot.id)} />
      ) : loading && !messages[bot.id] ? (
        <ChatSkeleton />
      ) : (
        <FlatList
          ref={listRef}
          data={list}
          keyExtractor={(m) => String(m.id)}
          renderItem={renderItem}
          style={styles.list}
          contentContainerStyle={[styles.messages, !list.length && styles.messagesEmpty]}
          ListEmptyComponent={welcome ?? undefined}
          ListFooterComponent={footer}
          onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: !reduceMotion })}
        />
      )}
      <View style={styles.dock}>
        <View style={styles.column}>
          {!canOnBot(bot, "manage") ? null : bot.tier?.managed && me?.role !== "admin" ? (
            <PlanBar label={bot.tier.label} />
          ) : (
            <ModelBar
              botId={bot.id}
              harness={bot.harness}
              model={bot.model}
              effort={bot.effort}
              tier={bot.tier?.managed ? bot.tier.name : undefined}
            />
          )}
          {canOperate ? (
            <View style={[styles.composer, composing && styles.composerFocused]}>
              <TextInput
                ref={inputRef}
                aria-label={`Message ${bot.name}`}
                style={styles.input}
                placeholder={`Message ${bot.name}`}
                placeholderTextColor={t.c.textFaint}
                value={text}
                onChangeText={edit}
                onFocus={() => setComposing(true)}
                onBlur={() => setComposing(false)}
                multiline
                onSubmitEditing={Platform.OS === "web" ? onSend : undefined}
              />
              <Pressable
                role="button"
                aria-label="Send"
                aria-disabled={!hasText}
                style={({ pressed }) => [styles.send, !hasText && styles.sendIdle, pressed && styles.pressed]}
                onPress={onSend}
              >
                <Text style={[styles.sendText, !hasText && styles.sendTextIdle]} maxFontSizeMultiplier={GLYPH_SCALE}>
                  ↑
                </Text>
              </Pressable>
            </View>
          ) : (
            <Text style={styles.readOnly}>{canWrite ? "You can view this Bot but not run it" : "Read-only access"}</Text>
          )}
        </View>
      </View>
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    chat: { flex: 1, backgroundColor: t.c.bg },
    empty: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: t.c.bg },
    header: {
      flexDirection: "row",
      alignItems: "center",
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.sm,
      minHeight: 56,
      borderBottomWidth: hairline,
      borderBottomColor: t.c.border,
      gap: t.space.sm,
    },
    backBtn: {
      width: 36,
      height: 36,
      borderRadius: t.radius.pill,
      alignItems: "center",
      justifyContent: "center",
      marginLeft: -t.space.xs,
    },
    backText: { color: t.c.text, fontSize: 30, lineHeight: 32, marginTop: -3 },
    pill: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.sm,
      flexShrink: 1,
      marginRight: "auto",
      paddingVertical: t.space.xs,
      paddingRight: t.space.sm,
      borderRadius: t.radius.pill,
    },
    pillName: { color: t.c.text, ...type(t, "lg"), fontWeight: t.font.weight.semibold, flexShrink: 1 },
    harnessChip: {
      backgroundColor: t.c.raised,
      borderColor: t.c.border,
      borderWidth: hairline,
      borderRadius: t.radius.pill,
      paddingHorizontal: t.space.sm,
      paddingVertical: t.space.xxs,
    },
    harness: { color: t.c.textMuted, ...type(t, "xs") },
    screenBtn: {
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.border,
      backgroundColor: t.c.raised,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.xs + 2,
    },
    screenBtnOn: { backgroundColor: t.c.accentSoft, borderColor: t.c.accentBorder },
    screenBtnText: { color: t.c.text, ...type(t, "sm"), fontWeight: t.font.weight.medium },
    screenBtnTextOn: { color: t.c.accentText },
    pressed: { opacity: 0.6 },
    column: { width: "100%", maxWidth: t.layout.chatColumn, alignSelf: "center" },
    list: { flex: 1 },
    messages: {
      width: "100%",
      maxWidth: t.layout.chatColumn,
      alignSelf: "center",
      paddingHorizontal: t.space.lg,
      paddingTop: t.space.lg,
      paddingBottom: t.space.xl,
    },
    messagesEmpty: { flexGrow: 1, justifyContent: "center" },
    ts: { color: t.c.textFaint, textAlign: "center", marginTop: t.space.md, marginBottom: t.space.lg, ...type(t, "xs") },
    routineRow: { alignItems: "center", marginVertical: t.space.sm },
    routine: {
      color: t.c.textMuted,
      ...type(t, "sm"),
      backgroundColor: t.c.surface,
      borderRadius: t.radius.pill,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.xs,
      overflow: "hidden",
    },
    row: { flexDirection: "row", marginBottom: t.space.lg },
    rowUser: { justifyContent: "flex-end" },
    reply: { flex: 1, minWidth: 0 },
    bubbleUser: {
      maxWidth: "80%",
      backgroundColor: t.c.userBubble,
      borderRadius: t.radius.xl,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.sm + 2,
    },
    bubbleError: {
      borderColor: t.c.danger,
      borderWidth: 1,
      backgroundColor: t.c.dangerSoft,
      borderRadius: t.radius.lg,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.sm,
    },
    userText: { color: t.c.text, ...type(t, "md") },
    from: { color: t.c.textMuted, ...type(t, "sm"), fontWeight: t.font.weight.medium, marginBottom: t.space.xs },
    copy: {
      alignSelf: "flex-start",
      marginTop: t.space.sm,
      paddingHorizontal: t.space.sm,
      paddingVertical: t.space.xxs,
      marginLeft: -t.space.sm,
      borderRadius: t.radius.pill,
    },
    copyText: { color: t.c.textFaint, ...type(t, "xs"), fontWeight: t.font.weight.medium },
    question: {
      marginTop: t.space.md,
      gap: t.space.sm,
      padding: t.space.md,
      borderRadius: t.radius.lg,
      backgroundColor: t.c.raised,
      borderWidth: hairline,
      borderColor: t.c.border,
      boxShadow: t.shadow.card,
    },
    qTitle: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.semibold, marginBottom: t.space.xs },
    opt: {
      borderWidth: 1,
      borderColor: t.c.border,
      borderRadius: t.radius.md,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.sm + 2,
      backgroundColor: t.c.bg,
    },
    optOn: { borderColor: t.c.accent, backgroundColor: t.c.accentSoft },
    optPressed: { backgroundColor: t.c.hover },
    openScreen: {
      alignSelf: "flex-start",
      backgroundColor: t.c.accent,
      borderRadius: t.radius.pill,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.sm,
      marginBottom: t.space.xxs,
    },
    openScreenText: { color: t.c.onAccent, fontWeight: t.font.weight.semibold },
    optText: { color: t.c.text, ...type(t, "md") },
    working: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      paddingVertical: t.space.sm,
    },
    workingText: { color: t.c.textMuted, flex: 1, ...type(t, "md") },
    stopBtn: {
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.border,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.xs,
    },
    stop: { color: t.c.danger, ...type(t, "sm"), fontWeight: t.font.weight.medium },
    dock: { paddingHorizontal: t.space.md, paddingBottom: t.space.md, paddingTop: t.space.xs },
    composer: {
      flexDirection: "row",
      alignItems: "flex-end",
      gap: t.space.sm,
      padding: t.space.sm,
      paddingLeft: t.space.lg,
      borderRadius: t.radius.xl + 2,
      borderWidth: 1,
      borderColor: t.c.border,
      backgroundColor: t.c.elevated,
      boxShadow: t.shadow.card,
    },
    // The input drops the browser's outline, so focus shows on the whole composer instead.
    composerFocused: {
      borderColor: t.c.accent,
      boxShadow: `${t.shadow.card}, 0 0 0 3px ${t.c.accentSoft}`,
    },
    input: {
      flex: 1,
      minHeight: 40,
      maxHeight: 160,
      paddingVertical: t.space.sm + 1,
      color: t.c.text,
      ...type(t, "md"),
      ...(Platform.OS === "web" ? { outlineStyle: "none" as never } : null),
    },
    send: {
      width: 38,
      height: 38,
      borderRadius: t.radius.pill,
      backgroundColor: t.c.accent,
      alignItems: "center",
      justifyContent: "center",
    },
    sendIdle: { backgroundColor: t.c.selected },
    sendText: { color: t.c.onAccent, fontSize: 20, lineHeight: 22, fontWeight: t.font.weight.bold },
    sendTextIdle: { color: t.c.textFaint },
    readOnly: { color: t.c.textFaint, textAlign: "center", padding: t.space.lg, ...type(t, "sm") },
  }),
);
