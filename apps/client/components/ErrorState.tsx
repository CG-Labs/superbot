import React, { useEffect, useRef, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { themedStyles, type } from "../src/theme";
import { PillButton } from "./PillButton";

/** Runs a retry, busy until a returned promise settles, ignoring presses while it runs. */
function useRetry(onRetry?: () => unknown): { busy: boolean; run: () => void } {
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  useEffect(
    () => () => {
      mounted.current = false;
    },
    [],
  );
  const run = () => {
    if (!onRetry || busy) return;
    const done = onRetry();
    if (!(done instanceof Promise)) return;
    setBusy(true);
    void done.catch(() => {}).finally(() => mounted.current && setBusy(false));
  };
  return { busy, run };
}

interface Props {
  title?: string;
  /** What went wrong, in plain words (see `friendlyError`). */
  message: string;
  /** Shows a "Try again" button; a returned promise keeps it busy until it settles. */
  onRetry?: () => unknown;
  retryLabel?: string;
}

/** Fills a screen or pane that couldn't load, with a way to try again. */
export function ErrorState({ title = "Something went wrong", message, onRetry, retryLabel = "Try again" }: Props) {
  const styles = useStyles();
  const { busy, run } = useRetry(onRetry);
  return (
    <View style={styles.full} testID="error-state">
      <View style={styles.circle} importantForAccessibility="no-hide-descendants" accessibilityElementsHidden>
        <Text style={styles.glyph} maxFontSizeMultiplier={1.2}>
          !
        </Text>
      </View>
      <View accessible role="alert" aria-live="assertive" style={styles.words}>
        <Text style={styles.title}>{title}</Text>
        <Text style={styles.message}>{message}</Text>
      </View>
      {onRetry ? (
        <View style={styles.actions}>
          <PillButton tone="primary" label={retryLabel} busy={busy} busyLabel="Trying…" onPress={run} />
        </View>
      ) : null}
    </View>
  );
}

/** A one-line error inside a list or card, with a retry link. */
export function InlineError({ message, onRetry, retryLabel = "Try again" }: Omit<Props, "title">) {
  const styles = useStyles();
  const { busy, run } = useRetry(onRetry);
  return (
    <View style={styles.inline} testID="inline-error">
      <Text style={styles.inlineText} role="alert" aria-live="polite">
        {message}
      </Text>
      {onRetry ? (
        <Pressable
          role="button"
          aria-label={busy ? "Trying…" : retryLabel}
          aria-disabled={busy}
          disabled={busy}
          hitSlop={8}
          onPress={run}
          style={({ pressed }) => [styles.inlineBtn, pressed && styles.pressed]}
        >
          <Text style={styles.inlineBtnText}>{busy ? "Trying…" : retryLabel}</Text>
        </Pressable>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    full: { flex: 1, alignItems: "center", justifyContent: "center", gap: t.space.sm, padding: t.space.xxl },
    circle: {
      width: 56,
      height: 56,
      borderRadius: t.radius.pill,
      backgroundColor: t.c.dangerSoft,
      alignItems: "center",
      justifyContent: "center",
      marginBottom: t.space.xs,
    },
    glyph: { color: t.c.danger, fontSize: 26, lineHeight: 30, fontWeight: t.font.weight.bold },
    words: { alignItems: "center", gap: t.space.sm },
    title: { color: t.c.text, ...type(t, "lg"), fontWeight: t.font.weight.semibold, textAlign: "center" },
    message: { color: t.c.textMuted, ...type(t, "md"), textAlign: "center", maxWidth: 380 },
    actions: { marginTop: t.space.md },
    inline: {
      flexDirection: "row",
      flexWrap: "wrap",
      alignItems: "center",
      alignSelf: "stretch",
      gap: t.space.sm,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.sm,
      borderRadius: t.radius.md,
      backgroundColor: t.c.dangerSoft,
    },
    inlineText: { flex: 1, minWidth: 160, color: t.c.danger, ...type(t, "sm") },
    inlineBtn: { paddingHorizontal: t.space.sm, paddingVertical: t.space.xxs, borderRadius: t.radius.pill },
    inlineBtnText: { color: t.c.danger, ...type(t, "sm"), fontWeight: t.font.weight.semibold, textDecorationLine: "underline" },
    pressed: { opacity: 0.6 },
  }),
);
