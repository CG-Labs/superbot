import React, { useState } from "react";
import { Modal, Pressable, ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import { errorText } from "../src/errors";
import { useReducedMotion } from "../src/motion";
import { focusFirst } from "../src/notifications";
import { useSuperBot } from "../src/SuperBotContext";
import { colors, ThemeScope, themedStyles, type } from "../src/theme";
import type { Approval, ApprovalScope } from "../src/types";
import { BotAvatar } from "./BotAvatar";
import { EmptyState } from "./EmptyState";

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
  const styles = useCardStyles();
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
      setError(errorText(err, "Couldn't send your answer"));
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
      {error ? (
        <Text style={styles.error} role="alert">
          {error}
        </Text>
      ) : null}
      {canDecide ? (
      <View style={styles.actions}>
        <Pressable style={({ pressed }) => [styles.btn, pressed && styles.pressed]} disabled={busy} onPress={() => void decide(false)} accessibilityRole="button">
          <Text style={styles.btnText}>Deny</Text>
        </Pressable>
        {canRun ? (
          <Pressable style={({ pressed }) => [styles.btn, pressed && styles.pressed]} disabled={busy} onPress={() => void decide(true, "run")} accessibilityRole="button" accessibilityHint={forRun ?? undefined}>
            <Text style={styles.btnText}>Approve for this run</Text>
          </Pressable>
        ) : null}
        <Pressable style={({ pressed }) => [styles.btn, styles.primary, pressed && styles.pressed]} disabled={busy} onPress={() => void decide(true)} accessibilityRole="button">
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
  const reduceMotion = useReducedMotion();

  return (
    <Modal visible={visible} animationType={reduceMotion ? "none" : "slide"} transparent onRequestClose={onClose}>
      <View style={styles.backdrop}>
        <View style={styles.panel}>
          <View style={styles.titleRow}>
            <Text style={styles.title} role="heading">
              Approvals
            </Text>
            <Pressable onPress={onClose} role="button" aria-label="Close approvals" hitSlop={8}>
              <Text style={styles.close} maxFontSizeMultiplier={1.3}>
                ✕
              </Text>
            </Pressable>
          </View>
          {gone ? (
            <Text style={styles.faint} accessibilityRole="alert">
              That approval isn't waiting anymore: someone answered it, or it timed out.
            </Text>
          ) : null}
          <ScrollView contentContainerStyle={{ gap: 12 }}>
            {list.length ? (
              <ThemeScope scheme="dark">
                {list.map((a) => (
                  <ApprovalCard key={a.id} approval={a} />
                ))}
              </ThemeScope>
            ) : (
              <ThemeScope scheme="dark">
                <EmptyState compact glyph="✓" title="You're all caught up" message="Nothing is waiting for you. Bots ask here before risky actions." />
              </ThemeScope>
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
  row: { flexDirection: "row", alignItems: "center", gap: 10 },
  dim: { color: colors.textDim },
  link: { color: colors.blueDot },
  faint: { color: colors.textFaint, fontSize: 13 },
});

const useCardStyles = themedStyles((t) =>
  StyleSheet.create({
    card: {
      flexGrow: 1,
      flexShrink: 1,
      minWidth: 0,
      backgroundColor: t.c.raised,
      borderRadius: t.radius.lg,
      borderWidth: 1,
      borderColor: t.c.border,
      borderLeftWidth: 3,
      borderLeftColor: t.c.warning,
      padding: t.space.lg,
      gap: t.space.sm,
      boxShadow: t.shadow.card,
    },
    head: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    who: { color: t.c.text, fontWeight: t.font.weight.semibold },
    reason: { color: t.c.warning, ...type(t, "md"), fontWeight: t.font.weight.medium },
    subject: {
      color: t.c.text,
      backgroundColor: t.c.codeBg,
      borderRadius: t.radius.md,
      padding: t.space.md,
      fontFamily: t.font.mono,
      fontSize: t.font.size.sm,
    },
    row: { flexDirection: "row", alignItems: "center", gap: t.space.md },
    actions: { flexDirection: "row", flexWrap: "wrap", justifyContent: "flex-end", gap: t.space.sm },
    btn: {
      paddingVertical: t.space.sm,
      paddingHorizontal: t.space.lg + 2,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.borderStrong,
    },
    btnText: { color: t.c.text, ...type(t, "md") },
    primary: { backgroundColor: t.c.accent, borderColor: t.c.accent },
    primaryText: { color: t.c.onAccent, fontWeight: t.font.weight.semibold },
    pressed: { opacity: 0.7 },
    dim: { color: t.c.textMuted },
    faint: { color: t.c.textFaint, ...type(t, "sm") },
    error: { color: t.c.danger },
  }),
);
