import React, { useCallback, useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { MARKDOWN } from "../src/fileTypes";
import { reportFileName, reportLabel, residencyLines } from "../src/residency";
import { saveCsv } from "../src/saveCsv";
import { themedStyles } from "../src/theme";
import type { MyResidency } from "../src/types";
import { kit, Spinner } from "./ui";

export type ResidencyApi = Pick<SuperBotApi, "myResidency" | "myResidencyReport">;

interface Props {
  api: ResidencyApi;
  /** Saves the report; the platform's download or share sheet unless a test swaps it. */
  save?: typeof saveCsv;
}

/**
 * The residency pin on your data (ADR 0168): where it must stay, whether it does, and the
 * residency report to download. Nothing shows when nothing pins your data.
 */
export function ResidencyCard({ api, save = saveCsv }: Props) {
  const styles = useStyles();
  const [view, setView] = useState<MyResidency | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<"user" | "team" | null>(null);

  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      setView(await api.myResidency());
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  if (view === undefined) {
    return (
      <View style={styles.card} accessibilityLabel="Data residency">
        <Text style={styles.cardTitle}>Data residency</Text>
        {loadError ? (
          <>
            <Text style={styles.error} accessibilityRole="alert">
              {`Couldn't load your data's residency: ${loadError}`}
            </Text>
            <Pressable style={styles.btn} onPress={() => void load()} accessibilityRole="button" accessibilityLabel="Try again">
              <Text style={styles.btnText}>Try again</Text>
            </Pressable>
          </>
        ) : (
          <Spinner />
        )}
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    card: k.card,
    cardTitle: k.cardTitle,
    line: k.text,
    good: k.good,
    error: k.error,
    warn: k.warn,
    dim: k.dim,
    row: k.actions,
    btn: { ...k.btn, alignSelf: "flex-start" },
    btnText: k.btnText,
    busy: k.disabled,
  });
});
