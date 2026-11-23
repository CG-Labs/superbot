import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { chainLines, shortHash, type ChainLine } from "../src/auditChain";
import { colors } from "../src/theme";
import type { AuditChainState, AuditVerifyReport } from "../src/types";

interface Props {
  api: Pick<SuperBotApi, "auditChain" | "auditVerify">;
}

const TONES: Record<ChainLine["tone"], string> = { ok: colors.accent, warn: colors.warning, bad: colors.danger, dim: colors.textDim };

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
  const [state, setState] = useState<AuditChainState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<ChainLine | null>(null);

  const load = useCallback(async () => {
    try {
      setState(await api.auditChain());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't load the chain's state");
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
      setResult({ label: "This check", text: err instanceof Error ? err.message : "The check failed", tone: "bad" });
    } finally {
      setChecking(false);
    }
  };

  const lines = state ? chainLines(state) : [];
  if (result) lines.unshift(result);
  return (
    <View style={styles.panel} testID="audit-chain">
      <View style={styles.top}>
        <Text style={styles.title}>Hash chain</Text>
        <Pressable onPress={() => void load()} accessibilityRole="button" accessibilityLabel="Refresh the chain's state">
          <Text style={styles.link}>Refresh</Text>
        </Pressable>
        <Pressable style={[styles.btn, checking && styles.busy]} onPress={() => void check()} disabled={checking} accessibilityRole="button" accessibilityState={{ disabled: checking, busy: checking }}>
          <Text style={styles.btnText}>{checking ? "Checking…" : "Check now"}</Text>
        </Pressable>
      </View>
      {error ? <Text style={styles.error}>{error}</Text> : null}
      {!state && !error ? <ActivityIndicator color={colors.textDim} /> : null}
      {lines.map((l) => (
        <View key={l.label} style={styles.line} accessibilityLabel={`${l.label}: ${l.text}`}>
          <View style={[styles.dot, { backgroundColor: TONES[l.tone] }]} />
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

const styles = StyleSheet.create({
  panel: { gap: 8, padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border, backgroundColor: colors.bgSidebar },
  top: { flexDirection: "row", alignItems: "center", gap: 16 },
  title: { color: colors.text, fontSize: 16, fontWeight: "600", flex: 1 },
  link: { color: colors.blueDot },
  btn: { borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingVertical: 6, paddingHorizontal: 14 },
  btnText: { color: colors.text },
  busy: { opacity: 0.6 },
  line: { flexDirection: "row", alignItems: "flex-start", gap: 8, flexWrap: "wrap" },
  dot: { width: 8, height: 8, borderRadius: 4, marginTop: 6 },
  label: { color: colors.textDim, width: 120 },
  text: { color: colors.text, flex: 1, minWidth: 200 },
  bad: { color: colors.danger },
  faint: { color: colors.textFaint, fontSize: 12, fontFamily: "monospace" },
  error: { color: colors.danger },
});
