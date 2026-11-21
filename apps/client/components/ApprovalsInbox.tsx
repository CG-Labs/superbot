import React, { useState } from "react";
import { Modal, Pressable, ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import { focusFirst } from "../src/notifications";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";
import type { Approval, ApprovalScope } from "../src/types";
import { BotAvatar } from "./BotAvatar";

interface Props {
  visible: boolean;
  onClose: () => void;
  /** Opens the policy editor for all Bots (ADR 0049). */
  onOpenPolicy?: () => void;
  /** The approval a notification linked to (ADR 0061): shown first, or noted as gone. */
  focusId?: string | null;
}

function minutesLeft(a: Approval): string {
  const m = Math.max(0, Math.ceil((a.expiresAt - Date.now()) / 60000));
  return m <= 1 ? "under a minute" : `${m} minutes`;
}

/** What "Approve for this run" lets through, in words (ADR 0051). */
export function runScopeText(a: Approval): string | null {
  const s = a.runScope;
  if (!s) return null;
  const what = s.exact || !s.covers.length ? "this exact call" : `calls like this (${s.covers.join("; ")})`;
  return `For this run, ${what} won't ask again until the task ends. Nothing is saved as a rule.`;
}

export function ApprovalCard({ approval: a }: { approval: Approval }) {
  const { bots, decideApproval, can, canOnBot } = useSuperBot();
  const bot = bots.find((b) => b.id === a.botId);
  // Answering lets the Bot act, so it takes operator access to that Bot (ADR 0017).
  const canDecide = can("approve") && canOnBot(bot, "operate");
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A run approval saves no rule, so it never goes with "remember".
  const forRun = runScopeText(a);
  const canRun = canDecide && !!forRun && !remember;

  const decide = async (approve: boolean, scope: ApprovalScope = "once") => {
    setBusy(true);
    setError(null);
    try {
      await decideApproval(a.id, approve, remember, scope);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
      setBusy(false);
    }
  };

  return (
    <View style={styles.card}>
      <View style={styles.head}>
        {bot ? <BotAvatar color={bot.color} shape={bot.shape} size={22} /> : null}
        <Text style={styles.who}>{bot?.name ?? "A Bot"}</Text>
        <Text style={styles.dim}>wants to run {a.tool}</Text>
      </View>
      <Text style={styles.reason}>{a.reason}</Text>
      <Text style={styles.subject} selectable>
        {a.subject}
      </Text>
      <View style={styles.row}>
        {can("admin") ? (
          <>
            <Switch value={remember} onValueChange={setRemember} />
            <Text style={[styles.dim, { flex: 1 }]}>Remember for {bot?.name ?? "this Bot"}</Text>
          </>
        ) : (
          <View style={{ flex: 1 }} />
        )}
        <Text style={styles.faint}>Denied in {minutesLeft(a)}</Text>
      </View>
      {canRun ? <Text style={styles.faint}>{forRun}</Text> : null}
      {error ? <Text style={styles.error}>{error}</Text> : null}
      {canDecide ? (
      <View style={styles.actions}>
        <Pressable style={styles.btn} disabled={busy} onPress={() => void decide(false)} accessibilityRole="button">
          <Text style={styles.btnText}>Deny</Text>
        </Pressable>
        {canRun ? (
          <Pressable style={styles.btn} disabled={busy} onPress={() => void decide(true, "run")} accessibilityRole="button" accessibilityHint={forRun ?? undefined}>
            <Text style={styles.btnText}>Approve for this run</Text>
          </Pressable>
        ) : null}
        <Pressable style={[styles.btn, styles.primary]} disabled={busy} onPress={() => void decide(true)} accessibilityRole="button">
          <Text style={[styles.btnText, styles.primaryText]}>Approve</Text>
        </Pressable>
      </View>
      ) : null}
    </View>
  );
}

export function ApprovalsInbox({ visible, onClose, onOpenPolicy, focusId }: Props) {
  const { approvals, policy, setGlobalPolicy, can } = useSuperBot();
  const ask = policy?.mode !== "bypass";
  const { list, gone } = focusFirst(approvals, focusId);

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <View style={styles.backdrop}>
        <View style={styles.panel}>
          <View style={styles.titleRow}>
            <Text style={styles.title}>Approvals</Text>
            <Pressable onPress={onClose}>
              <Text style={styles.close}>✕</Text>
            </Pressable>
          </View>
          {gone ? (
            <Text style={styles.faint} accessibilityRole="alert">
              That approval isn't waiting anymore: someone answered it, or it timed out.
            </Text>
          ) : null}
          <ScrollView contentContainerStyle={{ gap: 12 }}>
            {list.length ? (
              list.map((a) => <ApprovalCard key={a.id} approval={a} />)
            ) : (
              <Text style={styles.empty}>Nothing is waiting for you.</Text>
            )}
          </ScrollView>
          <View style={styles.row}>
            <Text style={[styles.dim, { flex: 1 }]}>Ask before risky actions (all Bots)</Text>
            <Switch
              value={ask}
              disabled={!can("admin")}
              onValueChange={(v) => void setGlobalPolicy(v ? "ask" : "bypass")}
            />
          </View>
          {!ask ? <Text style={styles.faint}>Bypass: Bots run everything without asking. Dev only.</Text> : null}
          {onOpenPolicy ? (
            <Pressable style={styles.row} onPress={onOpenPolicy} accessibilityRole="button">
              <Text style={styles.link}>{can("admin") ? "Edit risky actions, timeout, and rules ›" : "See risky actions, timeout, and rules ›"}</Text>
            </Pressable>
          ) : null}
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "flex-end" },
  panel: {
    backgroundColor: colors.bgSidebar,
    borderTopLeftRadius: 16,
    borderTopRightRadius: 16,
    padding: 20,
    maxHeight: "85%",
    gap: 12,
  },
  titleRow: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  title: { color: colors.text, fontSize: 20, fontWeight: "600" },
  close: { color: colors.textDim, fontSize: 22 },
  card: {
    backgroundColor: colors.bgBubble,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: "#3a2f1d",
    padding: 14,
    gap: 8,
  },
  head: { flexDirection: "row", alignItems: "center", gap: 8 },
  who: { color: colors.text, fontWeight: "500" },
  reason: { color: colors.warning, fontSize: 16 },
  subject: {
    color: colors.text,
    backgroundColor: "#151515",
    borderRadius: 10,
    padding: 10,
    fontFamily: "monospace",
    fontSize: 13,
  },
  row: { flexDirection: "row", alignItems: "center", gap: 10 },
  actions: { flexDirection: "row", flexWrap: "wrap", justifyContent: "flex-end", gap: 10 },
  btn: { paddingVertical: 8, paddingHorizontal: 18, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a" },
  btnText: { color: colors.text, fontSize: 15 },
  primary: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  primaryText: { color: "#111" },
  dim: { color: colors.textDim },
  link: { color: colors.blueDot },
  faint: { color: colors.textFaint, fontSize: 13 },
  error: { color: colors.danger },
  empty: { color: colors.textFaint, padding: 12, textAlign: "center" },
});
