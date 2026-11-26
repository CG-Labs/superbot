import React, { useState } from "react";
import {
  ActivityIndicator,
  Image,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  useWindowDimensions,
  View,
  type TextInputProps,
} from "react-native";
import { StatusBar } from "expo-status-bar";
import { hairline, themedStyles, type, useTheme } from "../src/theme";

/** Below this width the card's edge and shadow go, so a phone's whole screen is the card. */
const COMPACT = 520;

/**
 * The frame every sign-in step shares (ADR 0336): the SuperBot mark, a title and a line
 * under it, in a centred card that scrolls when the keyboard or a long list needs it.
 */
export function SignInFrame({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  const t = useTheme();
  const styles = useStyles();
  const compact = useWindowDimensions().width < COMPACT;
  return (
    <KeyboardAvoidingView style={styles.wrap} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <StatusBar style={t.scheme === "dark" ? "light" : "dark"} />
      <ScrollView contentContainerStyle={[styles.scroll, compact && styles.scrollCompact]} keyboardShouldPersistTaps="handled">
        <View style={[styles.card, !compact && styles.cardChrome]} testID="sign-in-card">
          <View style={styles.head}>
            <Image source={require("../assets/images/icon.png")} style={styles.mark} accessibilityIgnoresInvertColors />
            <Text style={styles.title} accessibilityRole="header">
              {title}
            </Text>
            {subtitle ? <Text style={styles.subtitle}>{subtitle}</Text> : null}
          </View>
          {children}
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

/** A labelled text box whose focus shows as an accent ring, on the web too. */
export function Field({ label, ...input }: { label: string } & TextInputProps) {
  const t = useTheme();
  const styles = useStyles();
  const [focused, setFocused] = useState(false);
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        accessibilityLabel={label}
        placeholderTextColor={t.c.textFaint}
        {...input}
        style={[styles.input, input.style, focused && styles.inputFocused]}
        onFocus={(e) => (setFocused(true), input.onFocus?.(e))}
        onBlur={(e) => (setFocused(false), input.onBlur?.(e))}
      />
    </View>
  );
}

/** The one accent-filled button on a step. */
export function PrimaryButton({ label, onPress, busy = false, disabled = false }: { label: string; onPress: () => void; busy?: boolean; disabled?: boolean }) {
  const t = useTheme();
  const styles = useStyles();
  const off = busy || disabled;
  return (
    <Pressable
      style={({ pressed }) => [styles.primary, off && styles.disabled, pressed && styles.pressed]}
      onPress={onPress}
      disabled={off}
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityState={{ disabled: off, busy }}
    >
      {busy ? <ActivityIndicator color={t.c.onAccent} /> : <Text style={styles.primaryText}>{label}</Text>}
    </Pressable>
  );
}

/** A quiet text button, for going back or signing out. */
export function TextButton({ label, onPress, disabled = false }: { label: string; onPress: () => void; disabled?: boolean }) {
  const styles = useStyles();
  return (
    <Pressable
      style={({ pressed }) => [styles.textBtn, disabled && styles.disabled, pressed && styles.pressed]}
      onPress={onPress}
      disabled={disabled}
      accessibilityRole="button"
    >
      <Text style={styles.textBtnText}>{label}</Text>
    </Pressable>
  );
}

/** A thin rule with a word in the middle, between single sign-on and the code box. */
export function Divider({ label }: { label: string }) {
  const styles = useStyles();
  return (
    <View style={styles.divider}>
      <View style={styles.rule} />
      <Text style={styles.dividerText}>{label}</Text>
      <View style={styles.rule} />
    </View>
  );
}

/** A soft card that says what went wrong (`danger`) or what's been done for you (`info`). */
export function Notice({ tone, children }: { tone: "danger" | "info"; children: string }) {
  const styles = useStyles();
  const danger = tone === "danger";
  return (
    <View
      style={[styles.notice, danger ? styles.noticeDanger : styles.noticeInfo]}
      accessible
      accessibilityRole={danger ? "alert" : undefined}
      accessibilityLiveRegion={danger ? "polite" : "none"}
    >
      <Text style={[styles.noticeText, danger ? styles.noticeDangerText : styles.noticeInfoText]}>{children}</Text>
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    wrap: { flex: 1, backgroundColor: t.c.bg },
    scroll: { flexGrow: 1, justifyContent: "center", padding: t.space.xl },
    scrollCompact: { padding: t.space.lg },
    card: { width: "100%", maxWidth: 440, alignSelf: "center", gap: t.space.lg, padding: t.space.sm },
    cardChrome: {
      padding: t.space.xxl,
      borderRadius: t.radius.xl,
      backgroundColor: t.c.raised,
      borderWidth: hairline,
      borderColor: t.c.border,
      boxShadow: t.shadow.card,
    },
    head: { alignItems: "center", gap: t.space.sm, marginBottom: t.space.sm },
    mark: { width: 56, height: 56, borderRadius: t.radius.lg, marginBottom: t.space.sm },
    title: { color: t.c.text, ...type(t, "xxl"), fontWeight: t.font.weight.semibold, textAlign: "center" },
    subtitle: { color: t.c.textMuted, ...type(t, "md"), textAlign: "center" },
    field: { gap: t.space.xs + 2 },
    label: { color: t.c.textMuted, ...type(t, "sm"), fontWeight: t.font.weight.medium },
    input: {
      backgroundColor: t.c.bg,
      borderColor: t.c.border,
      borderWidth: 1,
      borderRadius: t.radius.md,
      paddingHorizontal: t.space.md + 2,
      paddingVertical: t.space.md,
      color: t.c.text,
      ...type(t, "md"),
      ...(Platform.OS === "web" ? { outlineStyle: "none" as never } : null),
    },
    inputFocused: { borderColor: t.c.accent, boxShadow: `0 0 0 3px ${t.c.accentSoft}` },
    primary: {
      minHeight: 48,
      borderRadius: t.radius.pill,
      backgroundColor: t.c.accent,
      alignItems: "center",
      justifyContent: "center",
      paddingHorizontal: t.space.xl,
    },
    primaryText: { color: t.c.onAccent, ...type(t, "md"), fontWeight: t.font.weight.semibold },
    disabled: { opacity: 0.55 },
    pressed: { opacity: 0.75 },
    textBtn: { alignSelf: "center", paddingHorizontal: t.space.md, paddingVertical: t.space.sm, borderRadius: t.radius.pill },
    textBtnText: { color: t.c.textMuted, ...type(t, "md"), fontWeight: t.font.weight.medium },
    divider: { flexDirection: "row", alignItems: "center", gap: t.space.md },
    rule: { flex: 1, height: hairline, backgroundColor: t.c.borderStrong },
    dividerText: { color: t.c.textFaint, ...type(t, "sm") },
    notice: { borderRadius: t.radius.md, borderWidth: 1, paddingHorizontal: t.space.md + 2, paddingVertical: t.space.md },
    noticeDanger: { backgroundColor: t.c.dangerSoft, borderColor: t.c.danger },
    noticeInfo: { backgroundColor: t.c.accentSoft, borderColor: t.c.accentBorder },
    noticeText: { ...type(t, "sm") },
    noticeDangerText: { color: t.c.danger },
    noticeInfoText: { color: t.c.text },
  }),
);
