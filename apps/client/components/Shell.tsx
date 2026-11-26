import React, { useCallback, useEffect, useRef, useState } from "react";
import { AccessibilityInfo, Animated, Easing, Modal, Platform, ScrollView, StyleSheet, Text, View, type StyleProp, type ViewStyle } from "react-native";
import { router, type Href } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import { type Scheme, type Theme, themedStyles, useTheme } from "../src/theme";
import { kit, PageHeader } from "./ui";

/** Goes back a screen, or to `fallback` when there is none, as after a link or a reload. */
export function goBack(fallback: Href = "/home") {
  if (router.canGoBack()) router.back();
  else router.replace(fallback);
}

/** `goBack` as a handler for a back button. */
export function useGoBack(fallback: Href = "/home"): () => void {
  return useCallback(() => goBack(fallback), [fallback]);
}

/** `prefers-reduced-motion` on web, which can be read at once; native settings arrive later. */
function webPreference(): boolean | null {
  if (Platform.OS !== "web" || typeof window === "undefined" || !window.matchMedia) return null;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Whether the device asks for less motion (iOS and Android settings, `prefers-reduced-motion` on
 * web), following its changes; `null` until the setting is known.
 */
export function useMotionPreference(): boolean | null {
  const [reduced, setReduced] = useState(webPreference);
  useEffect(() => {
    let live = true;
    const set = (on: boolean) => live && setReduced(on);
    AccessibilityInfo.isReduceMotionEnabled()
      .then(set)
      .catch(() => live && setReduced((was) => was ?? false));
    const sub = AccessibilityInfo.addEventListener("reduceMotionChanged", set);
    return () => {
      live = false;
      sub.remove();
    };
  }, []);
  return reduced;
}

/**
 * A duration from the tokens' motion scale, or none when the device asks for less motion. Until
 * the setting is known nothing moves, so no one who asked for less motion sees a pane slide in.
 */
export function useMotion(): { reduced: boolean; duration: (speed: keyof Theme["motion"]) => number } {
  const t = useTheme();
  const reduced = useMotionPreference() !== false;
  const duration = useCallback((speed: keyof Theme["motion"]) => (reduced ? 0 : t.motion[speed]), [reduced, t]);
  return { reduced, duration };
}

/** How a modal comes in: a slide, or nothing with reduced motion. */
export function useModalAnimation(): "slide" | "none" {
  return useMotion().reduced ? "none" : "slide";
}

/** The root stack's options: the canvas behind every screen, and the platform's push unless the device asks for less motion. */
export function stackOptions(t: Theme, reduced: boolean) {
  return {
    headerShown: false,
    contentStyle: { backgroundColor: t.c.bg },
    animation: reduced ? ("none" as const) : ("default" as const),
  };
}

/** The status bar's text for a scheme: dark on the light canvas, light on the dark one. */
export function statusBarStyle(scheme: Scheme): "light" | "dark" {
  return scheme === "dark" ? "light" : "dark";
}

type Enter = "below" | "right" | "left";
const SHIFT = 12;

interface PaneProps {
  /** A change of key brings the new pane in. */
  paneKey?: string;
  /** Brings the first pane in too. */
  appear?: boolean;
  from?: Enter;
  style?: StyleProp<ViewStyle>;
  children?: React.ReactNode;
  testID?: string;
}

/**
 * Brings a pane in with a short fade and a small shift (the tokens' `base` duration) when its
 * key changes. With reduced motion it just shows it.
 */
export function PaneTransition({ paneKey, appear = false, from = "below", style, children, testID }: PaneProps) {
  const { reduced, duration } = useMotion();
  const progress = useRef(new Animated.Value(appear ? 0 : 1)).current;
  const shown = useRef<string | undefined | null>(appear ? null : paneKey);
  // The fade and shift apply only while a pane comes in, so a pane at rest has no transform.
  const [moving, setMoving] = useState(appear);

  useEffect(() => {
    if (shown.current === paneKey) return;
    shown.current = paneKey;
    const ms = duration("base");
    if (!ms) {
      progress.setValue(1);
      setMoving(false);
      return;
    }
    progress.setValue(0);
    setMoving(true);
    const run = Animated.timing(progress, {
      toValue: 1,
      duration: ms,
      easing: Easing.out(Easing.cubic),
      useNativeDriver: Platform.OS !== "web",
    });
    run.start(({ finished }) => finished && setMoving(false));
    return () => {
      run.stop();
      progress.setValue(1);
      setMoving(false);
    };
  }, [paneKey, duration, progress]);

  const shift = progress.interpolate({ inputRange: [0, 1], outputRange: [from === "left" ? -SHIFT : SHIFT, 0] });
  const motion = moving && !reduced ? { opacity: progress, transform: [from === "below" ? { translateY: shift } : { translateX: shift }] } : null;
  return (
    <Animated.View testID={testID} style={[style, motion]}>
      {children}
    </Animated.View>
  );
}

/**
 * The frame of a screen pushed over home: the safe area on the canvas. Native stacks animate
 * the push themselves; on web, where they don't, the screen fades in.
 */
export function RouteScreen({ children }: { children: React.ReactNode }) {
  const s = useStyles();
  return (
    <SafeAreaView style={s.root} edges={["top", "left", "right"]}>
      <PaneTransition appear={Platform.OS === "web"} style={s.fill} testID="route-screen">
        {children}
      </PaneTransition>
    </SafeAreaView>
  );
}

/** A screen someone can't use: its header, why not, and the way back. */
export function RouteNotice({ title, message, onBack }: { title: string; message: string; onBack: () => void }) {
  const s = useStyles();
  return (
    <View style={s.fill}>
      <PageHeader title={title} onBack={onBack} />
      <View style={s.center}>
        <Text style={s.text}>{message}</Text>
        <Text style={s.link} onPress={onBack}>
          Back to Bots
        </Text>
      </View>
    </View>
  );
}

interface SheetProps {
  visible: boolean;
  onClose: () => void;
  /** The back pill's text, naming the list it returns to ("‹ Users"). */
  backText: string;
  backLabel?: string;
  children: React.ReactNode;
}

/** On a phone, a list's detail as a full screen over it, with the same header and back pill as every screen. */
export function DetailSheet({ visible, onClose, backText, backLabel, children }: SheetProps) {
  const s = useStyles();
  return (
    <Modal visible={visible} animationType={useModalAnimation()} onRequestClose={onClose} testID="detail-sheet">
      <SafeAreaView style={s.root}>
        <PageHeader onBack={onClose} backText={backText} backLabel={backLabel} />
        <ScrollView contentContainerStyle={s.sheetBody}>{children}</ScrollView>
      </SafeAreaView>
    </Modal>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    fill: { flex: 1 },
    center: k.center,
    text: k.text,
    link: k.link,
    sheetBody: { padding: t.space.lg, paddingBottom: t.space.xxxl },
  });
});
