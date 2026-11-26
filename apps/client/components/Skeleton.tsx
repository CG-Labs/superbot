import React, { createContext, useContext, useEffect, useRef } from "react";
import {
  Animated,
  Platform,
  StyleSheet,
  useWindowDimensions,
  View,
  type DimensionValue,
  type StyleProp,
  type ViewStyle,
} from "react-native";
import { useReducedMotion } from "../src/motion";
import { themedStyles, useTheme } from "../src/theme";

const nativeDriver = Platform.OS !== "web";
const Pulse = createContext<Animated.Value | null>(null);

/** A slow fade every block in a group shares, so they breathe together; still when motion is reduced. */
function usePulse(): Animated.Value {
  const reduced = useReducedMotion();
  const { motion } = useTheme();
  const value = useRef(new Animated.Value(1)).current;
  useEffect(() => {
    value.setValue(1);
    if (reduced) return;
    const loop = Animated.loop(
      Animated.sequence([
        Animated.timing(value, { toValue: 0.45, duration: motion.slow * 3, useNativeDriver: nativeDriver }),
        Animated.timing(value, { toValue: 1, duration: motion.slow * 3, useNativeDriver: nativeDriver }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [reduced, value, motion.slow]);
  return value;
}

/**
 * Holds skeleton blocks in place of content that's loading. Screen readers hear one
 * "busy" element with `label` instead of a list of empty shapes.
 */
export function SkeletonGroup({ label, style, children }: { label: string; style?: StyleProp<ViewStyle>; children: React.ReactNode }) {
  const pulse = usePulse();
  return (
    <View accessible role="progressbar" aria-label={label} aria-busy style={style} testID="skeleton">
      <Pulse.Provider value={pulse}>{children}</Pulse.Provider>
    </View>
  );
}

/** One placeholder shape: a line of text by default. */
export function Skeleton({
  width = "100%",
  height = 14,
  radius,
  style,
}: {
  width?: DimensionValue;
  height?: DimensionValue;
  radius?: number;
  style?: StyleProp<ViewStyle>;
}) {
  const t = useTheme();
  const pulse = useContext(Pulse);
  return (
    <Animated.View
      style={[{ width, height, borderRadius: radius ?? t.radius.sm, backgroundColor: t.c.selected }, pulse ? { opacity: pulse } : null, style]}
    />
  );
}

function ChatLines() {
  const t = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.chat}>
      {[0, 1].map((i) => (
        <View key={i} style={styles.turn}>
          <Skeleton width="42%" height={40} radius={t.radius.xl} style={styles.userBubble} />
          <Skeleton width="94%" />
          <Skeleton width="82%" />
          <Skeleton width={i ? "38%" : "60%"} />
        </View>
      ))}
    </View>
  );
}

function ListRows({ rows, avatar }: { rows: number; avatar?: number }) {
  const t = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.rows}>
      {Array.from({ length: rows }, (_, i) => (
        <View key={i} style={styles.row}>
          {avatar ? <Skeleton width={avatar} height={avatar} radius={t.radius.pill} /> : null}
          <View style={styles.rowText}>
            <Skeleton width={i % 2 ? "46%" : "58%"} height={13} />
            <Skeleton width={i % 2 ? "72%" : "84%"} height={11} />
          </View>
        </View>
      ))}
    </View>
  );
}

/** A chat's history loading: a couple of turns in the chat column. */
export function ChatSkeleton() {
  const styles = useStyles();
  return (
    <SkeletonGroup label="Loading messages" style={styles.fill}>
      <ChatLines />
    </SkeletonGroup>
  );
}

/** A list loading, such as a Bot's routines: rows of two lines, with avatars when `avatar` is a size. */
export function ListSkeleton({ label, rows = 3, avatar }: { label: string; rows?: number; avatar?: number }) {
  return (
    <SkeletonGroup label={label}>
      <ListRows rows={rows} avatar={avatar} />
    </SkeletonGroup>
  );
}

/** The app starting: the shell's outline (the sidebar, and the chat on wide windows) instead of a blank screen. */
export function AppSkeleton() {
  const t = useTheme();
  const styles = useStyles();
  const { width } = useWindowDimensions();
  const wide = width >= 800;
  return (
    <SkeletonGroup label="Loading SuperBot" style={[styles.app, wide && styles.appWide]}>
      <View style={[styles.side, wide && styles.sideWide]}>
        <Skeleton width={96} height={18} />
        <Skeleton height={38} radius={t.radius.pill} style={styles.search} />
        <ListRows rows={5} avatar={40} />
      </View>
      {wide ? (
        <View style={styles.fill}>
          <View style={styles.header}>
            <Skeleton width={30} height={30} radius={t.radius.pill} />
            <Skeleton width={120} height={16} />
          </View>
          <ChatLines />
        </View>
      ) : null}
    </SkeletonGroup>
  );
}

/** Three dots that pulse in turn while a Bot works; still when motion is reduced. Decorative: pair it with text. */
export function ThinkingDots() {
  const reduced = useReducedMotion();
  const { motion } = useTheme();
  const styles = useStyles();
  const dots = useRef([0, 1, 2].map(() => new Animated.Value(0.35))).current;
  useEffect(() => {
    dots.forEach((d) => d.setValue(reduced ? 0.8 : 0.35));
    if (reduced) return;
    const all = Animated.parallel(
      dots.map((d, i) =>
        Animated.loop(
          Animated.sequence([
            Animated.delay(i * motion.fast),
            Animated.timing(d, { toValue: 1, duration: motion.slow, useNativeDriver: nativeDriver }),
            Animated.timing(d, { toValue: 0.35, duration: motion.slow, useNativeDriver: nativeDriver }),
            Animated.delay((dots.length - 1 - i) * motion.fast),
          ]),
        ),
      ),
    );
    all.start();
    return () => all.stop();
  }, [reduced, dots, motion.fast, motion.slow]);
  return (
    <View style={styles.dots} importantForAccessibility="no-hide-descendants" accessibilityElementsHidden testID="thinking-dots">
      {dots.map((d, i) => (
        <Animated.View key={i} style={[styles.dot, { opacity: d }]} />
      ))}
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    fill: { flex: 1 },
    chat: {
      width: "100%",
      maxWidth: t.layout.chatColumn,
      alignSelf: "center",
      paddingHorizontal: t.space.lg,
      paddingTop: t.space.xl,
      gap: t.space.xxl,
    },
    turn: { gap: t.space.sm },
    userBubble: { alignSelf: "flex-end", marginBottom: t.space.md },
    rows: { gap: t.space.md },
    row: { flexDirection: "row", alignItems: "center", gap: t.space.md, paddingVertical: t.space.xs },
    rowText: { flex: 1, gap: t.space.xs + 2 },
    app: { flex: 1, backgroundColor: t.c.bg },
    appWide: { flexDirection: "row" },
    side: { flex: 1, padding: t.space.lg, gap: t.space.md },
    sideWide: {
      flex: 0,
      width: t.layout.sidebar,
      backgroundColor: t.c.surface,
      borderRightWidth: StyleSheet.hairlineWidth,
      borderRightColor: t.c.border,
    },
    search: { marginBottom: t.space.sm },
    header: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.sm,
      minHeight: 56,
      paddingHorizontal: t.space.lg,
      borderBottomWidth: StyleSheet.hairlineWidth,
      borderBottomColor: t.c.border,
    },
    dots: { flexDirection: "row", alignItems: "center", gap: t.space.xs, paddingHorizontal: t.space.xxs },
    dot: { width: 7, height: 7, borderRadius: t.radius.pill, backgroundColor: t.c.accent },
  }),
);
