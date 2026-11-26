import React, { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AccessibilityInfo, Animated, Platform, Pressable, StyleSheet, Text, View } from "react-native";
import { SafeAreaInsetsContext } from "react-native-safe-area-context";
import { showError } from "../src/dialogs";
import { errorText } from "../src/errors";
import { useReducedMotion } from "../src/motion";
import { themedStyles, type, useTheme } from "../src/theme";

export type ToastTone = "info" | "success" | "error";

export interface ToastOptions {
  message: string;
  tone?: ToastTone;
  action?: { label: string; onPress: () => void };
  durationMs?: number;
}

export interface ToastApi {
  show: (toast: ToastOptions) => void;
  /** An error toast: `what` failed, then why in plain words, e.g. "Couldn't send your message. Can't reach the server…". */
  error: (err: unknown, what?: string, action?: ToastOptions["action"]) => void;
}

export const TOAST_MS = 4000;
/** Errors and toasts with an action stay longer, so there's time to read and act. */
export const TOAST_LONG_MS = 6000;

// Outside a ToastProvider (a screen rendered on its own), errors still reach the person as a dialog.
const dialogFallback: ToastApi = {
  show: (toast) => {
    if (toast.tone === "error") showError(new Error(toast.message));
  },
  error: (err, what) => showError(new Error(errorText(err, what))),
};

const ToastContext = createContext<ToastApi>(dialogFallback);

export function useToast(): ToastApi {
  return useContext(ToastContext);
}

type Shown = ToastOptions & { id: number };

/** Shows one short message at a time at the top of the app, read out by screen readers. */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toast, setToast] = useState<Shown | null>(null);
  const next = useRef(0);
  const api = useMemo<ToastApi>(() => {
    const show = (o: ToastOptions) => setToast({ ...o, id: ++next.current });
    return { show, error: (err, what, action) => show({ message: errorText(err, what), tone: "error", action }) };
  }, []);

  useEffect(() => {
    if (!toast) return;
    // iOS has no live regions; Android and the web read the toast's own live region.
    if (Platform.OS === "ios") AccessibilityInfo.announceForAccessibility(toast.message);
    const ms = toast.durationMs ?? (toast.action || toast.tone === "error" ? TOAST_LONG_MS : TOAST_MS);
    const timer = setTimeout(() => setToast((cur) => (cur?.id === toast.id ? null : cur)), ms);
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      {toast ? <ToastView key={toast.id} toast={toast} onDismiss={() => setToast(null)} /> : null}
    </ToastContext.Provider>
  );
}

function ToastView({ toast, onDismiss }: { toast: Shown; onDismiss: () => void }) {
  const t = useTheme();
  const styles = useStyles();
  const reduced = useReducedMotion();
  const top = useContext(SafeAreaInsetsContext)?.top ?? 0;
  const enter = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    if (reduced) {
      enter.setValue(1);
      return;
    }
    const anim = Animated.timing(enter, { toValue: 1, duration: t.motion.base, useNativeDriver: Platform.OS !== "web" });
    anim.start();
    return () => anim.stop();
  }, [enter, reduced, t.motion.base]);

  const tone = toast.tone ?? "info";
  const fg = tone === "error" ? styles.errorText : tone === "success" ? styles.successText : styles.infoText;
  const motion = reduced
    ? null
    : { opacity: enter, transform: [{ translateY: enter.interpolate({ inputRange: [0, 1], outputRange: [-8, 0] }) }] };

  return (
    <View pointerEvents="box-none" style={[styles.layer, { top: top + t.space.sm }]}>
      <Animated.View
        role={tone === "error" ? "alert" : "status"}
        aria-live={tone === "error" ? "assertive" : "polite"}
        style={[styles.toast, tone === "error" ? styles.error : tone === "success" ? styles.success : styles.info, motion]}
        testID="toast"
      >
        <Text style={[styles.message, fg]}>{toast.message}</Text>
        {toast.action ? (
          <Pressable
            role="button"
            aria-label={toast.action.label}
            hitSlop={8}
            onPress={() => {
              toast.action?.onPress();
              onDismiss();
            }}
            style={({ pressed }) => [styles.btn, pressed && styles.pressed]}
          >
            <Text style={[styles.action, fg]}>{toast.action.label}</Text>
          </Pressable>
        ) : null}
        <Pressable role="button" aria-label="Dismiss" hitSlop={8} onPress={onDismiss} style={({ pressed }) => [styles.btn, pressed && styles.pressed]}>
          <Text style={[styles.close, fg]} maxFontSizeMultiplier={1.3}>
            ✕
          </Text>
        </Pressable>
      </Animated.View>
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    layer: { position: "absolute", left: 0, right: 0, alignItems: "center", paddingHorizontal: t.space.md, zIndex: 1000 },
    toast: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.sm,
      maxWidth: 520,
      width: "100%",
      paddingLeft: t.space.lg,
      paddingRight: t.space.sm,
      paddingVertical: t.space.sm,
      borderRadius: t.radius.lg,
      borderWidth: 1,
      boxShadow: t.shadow.pop,
    },
    info: { backgroundColor: t.c.elevated, borderColor: t.c.border },
    success: { backgroundColor: t.c.successSoft, borderColor: t.c.successSoft },
    error: { backgroundColor: t.c.dangerSoft, borderColor: t.c.dangerSoft },
    message: { flex: 1, ...type(t, "md"), paddingVertical: t.space.xs },
    infoText: { color: t.c.text },
    successText: { color: t.c.success },
    errorText: { color: t.c.danger },
    btn: { paddingHorizontal: t.space.sm, paddingVertical: t.space.xs, borderRadius: t.radius.pill },
    pressed: { opacity: 0.6 },
    action: { ...type(t, "sm"), fontWeight: t.font.weight.semibold },
    close: { ...type(t, "md") },
  }),
);
