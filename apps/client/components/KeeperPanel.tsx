import React, { useCallback, useEffect, useRef, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import { keeperChoices, keeperQuestion } from "../src/access";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { errorText, friendlyError } from "../src/errors";
import { hairline, themedStyles, type } from "../src/theme";
import type { BotAccessView } from "../src/types";
import { Chips } from "./Chips";
import { InlineError } from "./ErrorState";
import { kit } from "./ui";

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
  const styles = useStyles();
  const [view, setView] = useState<BotAccessView | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Why the accounts didn't load, apart from a refused hand-over, so it can offer a retry. */
  const [loadError, setLoadError] = useState<string | null>(null);
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
      setLoadError(null);
    } catch (e) {
      setLoadError(errorText(e, "Couldn't load the service accounts"));
    }
  }, [api, botId, fetchView]);

  useEffect(() => {
    setView(null);
  }, [botId]);

  useEffect(() => {
    void load();
  }, [load, keptBy]);

  // Most Bots have no account to hand over to, so nothing shows until the list says there is one.
  if (!view) {
    return loadError ? (
      <View style={styles.wrap}>
        <InlineError message={loadError} onRetry={load} />
      </View>
    ) : null;
  }
  if (!view.keepers?.length) return null;
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
      setError(friendlyError(e));
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
      {loadError ? <InlineError message={loadError} onRetry={load} /> : null}
      {error ? <InlineError message={error} /> : null}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    wrap: { width: "100%", gap: t.space.sm, paddingVertical: t.space.sm, borderBottomWidth: hairline, borderBottomColor: t.c.border },
    dim: { color: t.c.textMuted, ...type(t, "md") },
    hint: k.dim,
  });
});
