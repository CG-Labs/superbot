import React, { useEffect, useRef, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { showError } from "../src/dialogs";
import { friendlyError } from "../src/errors";
import { themedStyles, type } from "../src/theme";
import type { Message } from "../src/types";
import { ErrorState } from "./ErrorState";
import { ScreenFrame } from "./ScreenFrame";
import { Skeleton, SkeletonGroup } from "./Skeleton";
import { kit } from "./ui";

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
  const styles = useStyles();
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [control, setControl] = useState(initialControl);
  const [finishing, setFinishing] = useState(false);
  /** Bumped by "Try again" to ask for the link now instead of at the next automatic retry. */
  const [attempt, setAttempt] = useState(0);
  const fetchRef = useRef(fetchUrl);
  fetchRef.current = fetchUrl;
  const controlChangeRef = useRef(onControlChange);
  controlChangeRef.current = onControlChange;

  useEffect(() => {
    controlChangeRef.current?.(control);
  }, [control]);

  /** The last link that worked, kept across failed refreshes and retries so a restarted screen is still noticed. */
  const lastRef = useRef<{ botId: string; url: string | null }>({ botId, url: null });

  useEffect(() => {
    let alive = true;
    if (lastRef.current.botId !== botId) lastRef.current = { botId, url: null };
    const last = lastRef.current;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setUrl(null);
    setError(null);
    const load = async () => {
      let wait = refreshMs;
      try {
        const next = await fetchRef.current(botId);
        if (!alive) return;
        // A new link means the screen restarted: back to view-only, like the web app.
        if (last.url !== null && next !== last.url) setControl(false);
        last.url = next;
        setUrl(next);
        setError(null);
      } catch (err) {
        if (!alive) return;
        setUrl(null);
        setError(friendlyError(err, "Can't open the screen."));
        wait = Math.min(retryMs, refreshMs);
      }
      timer = setTimeout(() => void load(), wait);
    };
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [botId, refreshMs, retryMs, attempt]);

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
        <Text style={styles.title} role="heading" numberOfLines={1}>
          {title}
        </Text>
        {handoff && onHandoffDone ? (
          <Pressable
            role="button"
            aria-label="Done, hand back to Bot"
            aria-busy={finishing}
            style={[styles.pill, styles.pillOn, finishing && styles.disabled]}
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
          style={[styles.pill, control && styles.pillOn, !url && styles.disabled]}
          disabled={!url}
          onPress={() => setControl((c) => !c)}
        >
          <Text style={control ? styles.pillTextOn : styles.pillText}>{control ? "Give back" : "Take over"}</Text>
        </Pressable>
        <Pressable role="button" aria-label="Close screen" style={styles.close} onPress={onClose}>
          <Text style={styles.closeText} maxFontSizeMultiplier={1.3}>
            ✕
          </Text>
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
        {!url && !error ? (
          <SkeletonGroup label={`Starting ${title}`} style={styles.cover}>
            <Skeleton width="70%" height="auto" radius={12} style={styles.placeholder} />
            <Text style={styles.msg}>Starting {title}…</Text>
          </SkeletonGroup>
        ) : null}
        {error ? (
          <View style={styles.cover}>
            <ErrorState title={`Can't show ${title}`} message={error} onRetry={() => setAttempt((n) => n + 1)} />
          </View>
        ) : null}
      </View>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: { flex: 1, backgroundColor: t.c.bg },
    bar: { minHeight: 60, flexDirection: "row", alignItems: "center", gap: 10, paddingHorizontal: t.space.lg },
    title: { flex: 1, color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.medium },
    pill: k.btn,
    pillOn: k.primary,
    pillText: k.btnText,
    pillTextOn: { ...k.btnText, ...k.primaryText },
    disabled: k.disabled,
    close: { padding: t.space.sm },
    closeText: { color: t.c.textMuted, fontSize: 20 },
    ask: { color: t.c.textMuted, ...type(t, "md"), paddingHorizontal: t.space.lg, paddingBottom: 10 },
    view: {
      flex: 1,
      marginHorizontal: t.space.lg,
      marginBottom: t.space.lg,
      borderRadius: t.radius.md,
      overflow: "hidden",
      // The remote display's letterbox, black in both schemes like the screen it frames.
      backgroundColor: "#000",
    },
    cover: { position: "absolute", top: 0, right: 0, bottom: 0, left: 0, alignItems: "center", justifyContent: "center", padding: t.space.xl, backgroundColor: t.c.surface },
    msg: { color: t.c.textMuted, textAlign: "center", marginTop: t.space.lg },
    placeholder: { maxWidth: 420, aspectRatio: 16 / 10 },
  });
});
