import React, { useCallback, useEffect, useRef, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import { keeperChoices, keeperQuestion } from "../src/access";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { colors } from "../src/theme";
import type { BotAccessView } from "../src/types";
import { Chips } from "./Chips";

interface Props {
  api: Pick<SuperBotApi, "getBotAccess" | "keepBot" | "releaseKeptBot">;
  botId: string;
  botName: string;
  /** Who keeps it, as the Bot list says: when that changes elsewhere, the panel reloads. */
  keptBy?: string | null;
}

/**
 * Which of the Bot owner's service accounts keeps it (ADR 0229), for its owner and admins:
 * the account then manages it within its role and tokens; the Bot stays the owner's. The
 * server offers only accounts that could keep it, and none on a primary Bot.
 */
export function KeeperPanel({ api, botId, botName, keptBy }: Props) {
  const [view, setView] = useState<BotAccessView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Only the latest request's answer is shown, so a slow older read can't undo a newer one.
  const latest = useRef(0);
  const fetchView = useCallback(
    async (req: () => Promise<BotAccessView>) => {
      const mine = ++latest.current;
      const v = await req();
      if (mine === latest.current) setView(v);
    },
    [],
  );

  const load = useCallback(async () => {
    try {
      await fetchView(() => api.getBotAccess(botId));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api, botId, fetchView]);

  useEffect(() => {
    setView(null);
  }, [botId]);

  useEffect(() => {
    void load();
  }, [load, keptBy]);

  if (error && !view) return <Text style={styles.error}>{error}</Text>;
  if (!view?.keepers?.length) return null;
  const current = view.serviceAccount?.id ?? "";
  const choices = keeperChoices(view);
  const nameOf = (id: string) => view.keepers?.find((k) => k.id === id)?.name ?? view.serviceAccount?.name ?? null;

  const pick = async (to: string) => {
    if (to === current) return;
    const q = keeperQuestion(botName, to ? nameOf(to) : null, current ? nameOf(current) : null);
    if (!(await confirmAsync(q.title, q.body, to ? "Hand it over" : "Take it back"))) return;
    setBusy(true);
    setError(null);
    try {
      await fetchView(() => (to ? api.keepBot(botId, to) : api.releaseKeptBot(botId)));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      // What the server holds now, keeping its refusal on screen.
      await fetchView(() => api.getBotAccess(botId)).catch(() => {});
    } finally {
      setBusy(false);
    }
  };

  return (
    <View style={styles.wrap}>
      <Text style={styles.dim}>Kept by a service account</Text>
      <Chips options={choices} value={current} onChange={(v) => void pick(v)} disabled={busy} />
      <Text style={styles.hint}>
        The account manages it within its role and tokens, at most {view.maxKeptBots ?? 20} Bots each. Its runs use the owner&apos;s keys and memory.
      </Text>
      {error ? <Text style={styles.error}>{error}</Text> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { width: "100%", gap: 8, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.border },
  dim: { color: colors.textDim },
  hint: { color: colors.textFaint, fontSize: 13 },
  error: { color: colors.danger, width: "100%" },
});
