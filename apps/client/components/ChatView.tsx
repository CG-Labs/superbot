import React, { useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  FlatList,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputInstance,
} from "react-native";
import Markdown from "react-native-markdown-display";
import { copyText, COPY_LABEL } from "../src/clipboard";
import { showError } from "../src/dialogs";
import { isOpenHandoff } from "../src/handoff";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";
import type { Message } from "../src/types";
import { ApprovalCard } from "./ApprovalsInbox";
import { BotAvatar } from "./BotAvatar";
import { HandoffBanner } from "./HandoffBanner";
import { ModelBar, PlanBar } from "./ModelBar";

interface Props {
  onOpenDetails: () => void;
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

export function ChatView({ onOpenDetails, onBack, onToggleScreen, screenOpen, prefill, onPrefilled }: Props) {
  const {
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
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const listRef = useRef<FlatList>(null);
  const inputRef = useRef<TextInputInstance>(null);

  const bot = bots.find((b) => b.id === activeId);
  const canOperate = canOnBot(bot, "operate");

  useEffect(() => {
    if (!activeId) return;
    setLoading(true);
    void loadMessages(activeId).finally(() => setLoading(false));
  }, [activeId, loadMessages]);

  useEffect(() => {
    if (prefill == null) return;
    setText(prefill);
    inputRef.current?.focus();
    onPrefilled?.();
    // onPrefilled is a new function on every parent render; only a new prefill matters.
  }, [prefill]);

  if (!bot) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyText}>Pick a bot to start chatting</Text>
      </View>
    );
  }

  const list = messages[bot.id] || [];
  const draft = drafts[bot.id];
  const handoff = handoffs[bot.id];

  const answer = (m: Message, option: number) => void answerQuestion(m, option).catch(showError);

  const onSend = () => {
    const t = text.trim();
    if (!t) return;
    setText("");
    void sendText(t);
  };

  const renderItem = ({ item, index }: { item: Message; index: number }) => {
    const prev = list[index - 1];
    const gap = !prev || item.at - prev.at > 30 * 60000;
    const isUser = item.role === "user";
    return (
      <View>
        {gap ? <Text style={styles.ts}>{formatTime(item.at)}</Text> : null}
        {item.role === "routine" ? (
          <Text style={styles.routine}>Routine · {item.text}</Text>
        ) : (
          <View style={[styles.row, isUser && styles.rowUser]}>
            <View style={[styles.bubble, isUser && styles.bubbleUser, item.error && styles.bubbleError]}>
              {item.role === "peer" || item.role === "reply" ? (
                <Text style={styles.from}>{peerLabel(item, bots)}</Text>
              ) : null}
              {isUser ? (
                <Text style={styles.userText}>{item.text}</Text>
              ) : (
                <Markdown style={mdStyles}>{item.text}</Markdown>
              )}
              {!isUser && item.text ? (
                <Pressable
                  role="button"
                  aria-label={`${COPY_LABEL} message`}
                  style={styles.copy}
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
                      style={styles.openScreen}
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
                      style={[styles.opt, item.question?.picked === k && styles.optOn]}
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
          <View style={styles.bubble}>
            <Markdown style={mdStyles}>{draft}</Markdown>
          </View>
        </View>
      ) : null}
      {bot.working ? (
        <View style={styles.working}>
          <ActivityIndicator color={colors.blueDot} />
          <Text style={styles.workingText}>{bot.status || "Working"}…</Text>
          {canOperate ? (
            <Pressable onPress={() => void stopBot(bot.id)}>
              <Text style={styles.stop}>Stop</Text>
            </Pressable>
          ) : null}
        </View>
      ) : null}
    </View>
  );

  return (
    <View style={styles.chat}>
      <View style={styles.header}>
        {onBack ? (
          <Pressable onPress={onBack} style={styles.backBtn}>
            <Text style={styles.backText}>←</Text>
          </Pressable>
        ) : null}
        <Pressable style={styles.pill} onPress={onOpenDetails}>
          <BotAvatar color={bot.color} shape={bot.shape} size={30} />
          <Text style={styles.pillName}>{bot.name}</Text>
          <Text style={styles.harness}>{bot.harness}</Text>
        </Pressable>
        {canOperate ? (
        <Pressable
          role="button"
          aria-label={screenOpen ? "Hide screen" : "Show screen"}
          aria-pressed={!!screenOpen}
          style={[styles.screenBtn, screenOpen && styles.screenBtnOn]}
          onPress={() => onToggleScreen()}
        >
          <Text style={styles.screenBtnText}>Screen</Text>
        </Pressable>
        ) : null}
      </View>
      {handoff ? (
        <HandoffBanner botName={bot.name} handoff={handoff} onOpenScreen={() => onToggleScreen(true)} />
      ) : null}
      {loading ? (
        <ActivityIndicator style={{ marginTop: 24 }} color={colors.textDim} />
      ) : (
        <FlatList
          ref={listRef}
          data={list}
          keyExtractor={(m) => String(m.id)}
          renderItem={renderItem}
          contentContainerStyle={styles.messages}
          ListFooterComponent={footer}
          onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: true })}
        />
      )}
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
      <View style={styles.composer}>
        <TextInput
          ref={inputRef}
          aria-label={`Message ${bot.name}`}
          style={styles.input}
          placeholder={`Message ${bot.name}`}
          placeholderTextColor={colors.textFaint}
          value={text}
          onChangeText={setText}
          multiline
          onSubmitEditing={Platform.OS === "web" ? onSend : undefined}
        />
        <Pressable style={styles.send} onPress={onSend}>
          <Text style={styles.sendText}>Send</Text>
        </Pressable>
      </View>
      ) : (
        <Text style={styles.readOnly}>{canWrite ? "You can view this Bot but not run it" : "Read-only access"}</Text>
      )}
    </View>
  );
}

const mdStyles = StyleSheet.create({
  body: { color: colors.text, fontSize: 15 },
  code_inline: { backgroundColor: "#2a2a2a", borderRadius: 4 },
  fence: { backgroundColor: "#111", padding: 8, borderRadius: 8 },
});

const styles = StyleSheet.create({
  chat: { flex: 1, backgroundColor: colors.bgMain },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: colors.bgMain },
  emptyText: { color: colors.textDim },
  header: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    gap: 8,
  },
  backBtn: { padding: 8 },
  backText: { color: colors.text, fontSize: 22 },
  pill: { flexDirection: "row", alignItems: "center", gap: 8, flex: 1 },
  pillName: { color: colors.text, fontSize: 16, fontWeight: "600" },
  harness: { color: colors.textFaint, fontSize: 13 },
  screenBtn: { backgroundColor: colors.bgBubble, borderRadius: 999, paddingHorizontal: 14, paddingVertical: 6 },
  screenBtnOn: { backgroundColor: colors.bgActive, borderWidth: 1, borderColor: colors.blue },
  screenBtnText: { color: colors.text, fontSize: 14 },
  messages: { padding: 12, paddingBottom: 24 },
  ts: { color: colors.textFaint, textAlign: "center", marginVertical: 10, fontSize: 13 },
  routine: { color: colors.textFaint, textAlign: "center", marginVertical: 6, fontSize: 13 },
  row: { flexDirection: "row", marginBottom: 8 },
  rowUser: { justifyContent: "flex-end" },
  bubble: {
    maxWidth: "88%",
    backgroundColor: colors.bgBubble,
    borderRadius: 16,
    paddingHorizontal: 14,
    paddingVertical: 10,
  },
  bubbleUser: { backgroundColor: "#2a3344" },
  bubbleError: { borderColor: colors.danger, borderWidth: 1 },
  userText: { color: colors.text },
  from: { color: colors.textFaint, fontSize: 13, marginBottom: 2 },
  copy: { alignSelf: "flex-start", marginTop: 4 },
  copyText: { color: colors.textFaint, fontSize: 12 },
  question: { marginTop: 8, gap: 6 },
  qTitle: { color: colors.text, fontWeight: "600", marginBottom: 4 },
  opt: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    padding: 10,
  },
  optOn: { borderColor: colors.blue },
  openScreen: {
    alignSelf: "flex-start",
    backgroundColor: colors.blue,
    borderRadius: 999,
    paddingHorizontal: 14,
    paddingVertical: 7,
    marginBottom: 2,
  },
  openScreenText: { color: "#fff", fontWeight: "600" },
  optText: { color: colors.text },
  working: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    padding: 12,
  },
  workingText: { color: colors.textDim, flex: 1 },
  stop: { color: colors.danger },
  composer: {
    flexDirection: "row",
    alignItems: "flex-end",
    gap: 8,
    padding: 12,
    borderTopWidth: 1,
    borderTopColor: colors.border,
  },
  input: {
    flex: 1,
    minHeight: 44,
    maxHeight: 120,
    backgroundColor: colors.bgBubble,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
  },
  send: {
    backgroundColor: colors.blue,
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  sendText: { color: "#fff", fontWeight: "600" },
  readOnly: { color: colors.textFaint, textAlign: "center", padding: 16 },
});