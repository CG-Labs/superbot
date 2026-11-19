import React, { useEffect, useRef, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from "react-native";
import { showError } from "../src/dialogs";
import { colors } from "../src/theme";
import type { Message } from "../src/types";
import { ScreenFrame } from "./ScreenFrame";

/** The server stops idle screens; re-asking for the link while watching keeps this one up. */
export const SCREEN_REFRESH_MS = 60_000;
/** A screen that is starting or busy usually works again within seconds. */
export const SCREEN_RETRY_MS = 3_000;

interface Props {
  botId: string;
  botName: string;
  fetchUrl: (botId: string) => Promise<string>;
  onClose: () => void;
  /** Start with control (e.g. opened from a handoff card) instead of view-only. */
  initialControl?: boolean;
  /** The open handoff for this Bot, if any: shows "Done" to hand the screen back. */
  handoff?: Message;
  onHandoffDone?: () => Promise<void>;
  /** Reports take over / give back, so a remounted viewer (e.g. after a layout change) keeps the same state. */
  onControlChange?: (control: boolean) => void;
  refreshMs?: number;
  retryMs?: number;
}

export function ScreenViewer({
  botId,
  botName,
  fetchUrl,
  onClose,
  initialControl = false,
  handoff,
  onHandoffDone,
  onControlChange,
  refreshMs = SCREEN_REFRESH_MS,
  retryMs = SCREEN_RETRY_MS,
}: Props) {
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [control, setControl] = useState(initialControl);
  const [finishing, setFinishing] = useState(false);
  const fetchRef = useRef(fetchUrl);
  fetchRef.current = fetchUrl;
  const controlChangeRef = useRef(onControlChange);
  controlChangeRef.current = onControlChange;

  useEffect(() => {
    controlChangeRef.current?.(control);
  }, [control]);

  useEffect(() => {
    let alive = true;
    // The last link that worked, kept across failed refreshes so a restarted screen is still noticed.
    let last: string | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setUrl(null);
    setError(null);
    const load = async () => {
      let wait = refreshMs;
      try {
        const next = await fetchRef.current(botId);
        if (!alive) return;
        // A new link means the screen restarted: back to view-only, like the web app.
        if (last !== null && next !== last) setControl(false);
        last = next;
        setUrl(next);
        setError(null);
      } catch (err) {
        if (!alive) return;
        setUrl(null);
        setError(err instanceof Error ? err.message : "Can't open the screen");
        wait = Math.min(retryMs, refreshMs);
      }
      timer = setTimeout(() => void load(), wait);
    };
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [botId, refreshMs, retryMs]);

  const title = `${botName}'s screen`;

  const finish = async () => {
    if (!onHandoffDone) return;
    setFinishing(true);
    try {
      await onHandoffDone();
      setControl(false);
    } catch (err) {
      showError(err);
    } finally {
      setFinishing(false);
    }
  };

  return (
    <View style={styles.root}>
      <View style={styles.bar}>
        <Text style={styles.title} numberOfLines={1}>
          {title}
        </Text>
        {handoff && onHandoffDone ? (
          <Pressable
            role="button"
            aria-label="Done, hand back to Bot"
            style={[styles.pill, styles.done]}
            disabled={finishing}
            onPress={() => void finish()}
          >
            <Text style={styles.pillTextOn}>{finishing ? "Sending…" : "Done"}</Text>
          </Pressable>
        ) : null}
        <Pressable
          role="button"
          aria-label={control ? "Give back" : "Take over"}
          aria-pressed={control}
          style={[styles.pill, control && styles.pillOn]}
          disabled={!url}
          onPress={() => setControl((c) => !c)}
        >
          <Text style={control ? styles.pillTextOn : styles.pillText}>{control ? "Give back" : "Take over"}</Text>
        </Pressable>
        <Pressable role="button" aria-label="Close screen" style={styles.close} onPress={onClose}>
          <Text style={styles.closeText}>✕</Text>
        </Pressable>
      </View>
      {handoff ? (
        <Text style={styles.ask} numberOfLines={2}>
          {botName} needs you: {handoff.question?.title}
        </Text>
      ) : null}
      <View style={styles.view}>
        {url ? <ScreenFrame url={url} title={title} /> : null}
        {url && !control ? (
          <View
            testID="screen-shield"
            aria-label="View only. Take over to use this screen."
            style={StyleSheet.absoluteFill}
          />
        ) : null}
        {!url && !error ? <ActivityIndicator style={styles.center} color={colors.textDim} /> : null}
        {error ? (
          <View style={styles.center}>
            <Text style={styles.msg}>{error}</Text>
          </View>
        ) : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#111" },
  bar: { height: 60, flexDirection: "row", alignItems: "center", gap: 10, paddingHorizontal: 16 },
  title: { flex: 1, color: "#dcdcdc", fontSize: 16 },
  pill: { backgroundColor: "#1f1f1f", paddingHorizontal: 16, paddingVertical: 8, borderRadius: 999 },
  pillOn: { backgroundColor: colors.blue },
  done: { backgroundColor: colors.accent },
  pillText: { color: colors.text, fontSize: 15 },
  pillTextOn: { color: "#fff", fontSize: 15, fontWeight: "600" },
  close: { padding: 8 },
  closeText: { color: colors.textDim, fontSize: 20 },
  ask: { color: colors.textDim, paddingHorizontal: 16, paddingBottom: 10 },
  view: {
    flex: 1,
    marginHorizontal: 16,
    marginBottom: 16,
    borderRadius: 12,
    overflow: "hidden",
    backgroundColor: "#000",
  },
  center: { position: "absolute", top: 0, right: 0, bottom: 0, left: 0, alignItems: "center", justifyContent: "center", padding: 24 },
  msg: { color: colors.textDim, textAlign: "center" },
});
