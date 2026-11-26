import React, { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import { useOnline } from "../src/online";
import { themedStyles, type } from "../src/theme";
import { ThinkingDots } from "./Skeleton";

export type ConnectionStatus = "online" | "reconnecting" | "offline";

/** A blip shorter than this (the stream reconnecting on its own) shows nothing. */
export const RECONNECT_GRACE_MS = 1500;

/**
 * Offline when the device says so; reconnecting once the live event stream has been down
 * for `graceMs`; otherwise online.
 */
export function useConnectionStatus(connected: boolean, graceMs = RECONNECT_GRACE_MS): ConnectionStatus {
  const online = useOnline();
  const [late, setLate] = useState(false);
  useEffect(() => {
    setLate(false);
    if (connected) return;
    const timer = setTimeout(() => setLate(true), graceMs);
    return () => clearTimeout(timer);
  }, [connected, graceMs]);
  if (!online) return "offline";
  return !connected && late ? "reconnecting" : "online";
}

/** A slim strip at the top of the app while it's offline or reconnecting; nothing while online. */
export function ConnectionBanner({ status }: { status: ConnectionStatus }) {
  const styles = useStyles();
  if (status === "online") return null;
  const offline = status === "offline";
  return (
    <View role="status" aria-live="polite" style={[styles.banner, offline ? styles.offline : styles.reconnecting]} testID="connection-banner">
      {offline ? null : <ThinkingDots />}
      <Text style={[styles.text, offline ? styles.offlineText : styles.reconnectingText]}>
        {offline ? "You're offline. Chats catch up when you're back." : "Reconnecting… New messages show up once you're back."}
      </Text>
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    banner: {
      flexDirection: "row",
      alignItems: "center",
      justifyContent: "center",
      gap: t.space.sm,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.xs + 2,
    },
    offline: { backgroundColor: t.c.warningSoft },
    reconnecting: { backgroundColor: t.c.accentSoft },
    text: { ...type(t, "sm"), fontWeight: t.font.weight.medium, textAlign: "center", flexShrink: 1 },
    offlineText: { color: t.c.warning },
    reconnectingText: { color: t.c.accentText },
  }),
);
