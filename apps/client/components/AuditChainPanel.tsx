import React, { useCallback, useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { chainLines, shortHash, type ChainLine } from "../src/auditChain";
import { errorText, friendlyError } from "../src/errors";
import { hairline, type Theme, themedStyles, type, useTheme } from "../src/theme";
import type { AuditChainState, AuditVerifyReport } from "../src/types";
import { InlineError } from "./ErrorState";
import { ListSkeleton } from "./Skeleton";
import { kit } from "./ui";

interface Props {
  api: Pick<SuperBotApi, "auditChain" | "auditVerify">;
}

const tones = (t: Theme): Record<ChainLine["tone"], string> => ({ ok: t.c.success, warn: t.c.warning, bad: t.c.danger, dim: t.c.textMuted });

function checkResult(r: AuditVerifyReport): ChainLine {
  const c = r.checkpoints;
  if (r.ok) {
    const signed = c ? `, ${c.checked} checkpoints, ${c.timestamped} timestamps` : "";
    return { label: "This check", text: `Intact: ${r.checked} events${signed}. Head ${shortHash(r.head?.hash)}`, tone: "ok" };
  }
  const why = c?.firstBroken ? `: ${c.firstBroken.error}` : "";
  const where = r.firstBroken ? `at event ${r.firstBroken.id} (${r.firstBroken.reason})` : (r.error ?? "");
  return { label: "This check", text: `Broken ${where}${why}`, tone: "bad" };
}

/** The audit chain's state, read-only (ADR 0149): last check, head, signed checkpoint, timestamps, SIEM lag. */
export function AuditChainPanel({ api }: Props) {
  const styles = useStyles();
  const tone = tones(useTheme());
  const [state, setState] = useState<AuditChainState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<ChainLine | null>(null);

  const load = useCallback(async () => {
    try {
      setState(await api.auditChain());
      setError(null);
    } catch (err) {
      setError(errorText(err, "Couldn't load the chain's state"));
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const check = async () => {
    setChecking(true);
    try {
      setResult(checkResult(await api.auditVerify()));
      await load();
    } catch (err) {
      setResult({ label: "This check", text: friendlyError(err, "The check failed. Try again."), tone: "bad" });
    } finally {
      setChecking(false);
    }
  };

  const lines = state ? chainLines(state) : [];
  if (result) lines.unshift(result);
  return (
    <View style={styles.panel} testID="audit-chain">
      <View style={styles.top}>
        <Text style={styles.title} role="heading">
          Hash chain
        </Text>
        <Pressable onPress={() => void load()} accessibilityRole="button" accessibilityLabel="Refresh the chain's state" style={styles.refresh}>
          <Text style={styles.link}>Refresh</Text>
        </Pressable>
        <Pressable style={({ pressed }) => [styles.btn, pressed && styles.btnPressed, checking && styles.busy]} onPress={() => void check()} disabled={checking} accessibilityRole="button" accessibilityState={{ disabled: checking, busy: checking }}>
          <Text style={styles.btnText}>{checking ? "Checking…" : "Check now"}</Text>
        </Pressable>
      </View>
      {error ? <InlineError message={error} onRetry={load} /> : null}
      {!state && !error ? <ListSkeleton label="Checking the chain" rows={2} /> : null}
      {lines.map((l, i) => (
        <View key={`${i}:${l.label}`} style={[styles.line, i === 0 && styles.lineFirst]} accessible accessibilityLabel={`${l.label}: ${l.text}`}>
          <View style={[styles.dot, { backgroundColor: tone[l.tone] }]} />
          <Text style={styles.label}>{l.label}</Text>
          <Text style={[styles.text, l.tone === "bad" && styles.bad]} selectable>
            {l.text}
          </Text>
        </View>
      ))}
      {state ? (
        <Text style={styles.faint} selectable>
          Checkpoint key {state.checkpoints.key.id} ({state.checkpoints.key.algorithm}): {state.checkpoints.key.publicKey}
        </Text>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    panel: { ...k.card, gap: t.space.xs, marginHorizontal: t.space.lg, marginTop: t.space.md, marginBottom: t.space.xs },
    top: { flexDirection: "row", alignItems: "center", gap: t.space.sm, marginBottom: t.space.xs },
    title: { ...k.cardTitle, flex: 1 },
    refresh: { paddingHorizontal: t.space.sm, paddingVertical: t.space.xs },
    link: k.link,
    btn: { ...k.btn, ...k.btnSmall },
    btnPressed: k.btnPressed,
    btnText: k.btnText,
    busy: k.disabled,
    line: { ...k.row, alignItems: "flex-start", flexWrap: "wrap", gap: t.space.sm, paddingVertical: t.space.sm },
    lineFirst: k.rowFirst,
    dot: {
      width: t.space.sm,
      height: t.space.sm,
      borderRadius: t.radius.pill,
      marginTop: (t.font.lineHeight.sm - t.space.sm) / 2,
    },
    label: { ...k.dim, width: 120 },
    text: { color: t.c.text, ...type(t, "sm"), flex: 1, minWidth: 200 },
    bad: { color: t.c.danger },
    faint: { ...k.faint, fontFamily: t.font.mono, paddingTop: t.space.sm, borderTopWidth: hairline, borderTopColor: t.c.border },
  });
});
