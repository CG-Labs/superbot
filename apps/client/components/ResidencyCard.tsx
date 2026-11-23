import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { MARKDOWN } from "../src/fileTypes";
import { reportFileName, reportLabel, residencyLines } from "../src/residency";
import { saveCsv } from "../src/saveCsv";
import { colors } from "../src/theme";
import type { MyResidency } from "../src/types";

export type ResidencyApi = Pick<SuperBotApi, "myResidency" | "myResidencyReport">;

interface Props {
  api: ResidencyApi;
  /** Saves the report; the platform's download or share sheet unless a test swaps it. */
  save?: typeof saveCsv;
}

/**
 * The residency pin on your data (ADR 0166): where it must stay, whether it does, and the
 * residency report to download. Nothing shows when nothing pins your data.
 */
export function ResidencyCard({ api, save = saveCsv }: Props) {
  const [view, setView] = useState<MyResidency | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<"user" | "team" | null>(null);

  const load = useCallback(async () => {
    try {
      setView(await api.myResidency());
    } catch {
      setView(null);
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  if (view === undefined) {
    return (
      <View style={styles.card} accessibilityLabel="Data residency">
        <Text style={styles.cardTitle}>Data residency</Text>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }
  if (!view?.pin) return null;

  const download = async (on: "user" | "team") => {
    setBusy(on);
    setError(null);
    setNotice(null);
    try {
      const r = await api.myResidencyReport(on);
      await save(reportFileName(on, r.fileName), r.text, "Save residency report", MARKDOWN);
      setNotice("Report saved. Its digest, at the end, shows it hasn't been changed.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const { lines, warnings } = residencyLines(view);
  return (
    <View style={styles.card} accessibilityLabel="Data residency">
      <Text style={styles.cardTitle}>Data residency</Text>
      {lines.map((l) => (
        <Text key={l} style={styles.line}>
          {l}
        </Text>
      ))}
      {warnings.map((w) => (
        <Text key={w} style={styles.warn} accessibilityRole="alert">
          {w}
        </Text>
      ))}
      <Text style={styles.dim}>The pin covers your computer, its backups and your Bots' AI models. Chats and accounts are kept where this server runs.</Text>
      {notice ? (
        <Text style={styles.good} accessibilityRole="alert">
          {notice}
        </Text>
      ) : null}
      {error ? (
        <Text style={styles.error} accessibilityRole="alert">
          {error}
        </Text>
      ) : null}
      {view.reports.length ? (
        <View style={styles.row}>
          {view.reports.map((on) => (
            <Pressable key={on} style={[styles.btn, busy && styles.busy]} disabled={!!busy} onPress={() => void download(on)} accessibilityRole="button" accessibilityLabel={reportLabel(on)}>
              <Text style={styles.btnText}>{busy === on ? "Preparing…" : reportLabel(on)}</Text>
            </Pressable>
          ))}
        </View>
      ) : view.pin.on === "team" ? (
        <Text style={styles.dim}>Your team's owners and admins can download its residency report.</Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 10, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  line: { color: colors.text, fontSize: 14 },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
  row: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  btn: { alignSelf: "flex-start", borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingVertical: 8, paddingHorizontal: 16 },
  btnText: { color: colors.text, fontSize: 15 },
  busy: { opacity: 0.6 },
});
