import React from "react";
import { Pressable, StyleSheet, Text, View, type StyleProp, type ViewStyle } from "react-native";
import { hairline, type Theme, themedStyles, type, useTheme } from "../src/theme";

const build = (t: Theme) =>
  StyleSheet.create({
    root: { flex: 1, backgroundColor: t.c.bg },
    center: { flex: 1, alignItems: "center", justifyContent: "center", gap: t.space.md, padding: t.space.xl, backgroundColor: t.c.bg },
    header: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      minHeight: 56,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.sm,
      backgroundColor: t.c.bg,
      borderBottomWidth: hairline,
      borderBottomColor: t.c.border,
    },
    back: {
      flexDirection: "row",
      alignItems: "center",
      minHeight: 36,
      paddingVertical: t.space.xs,
      paddingHorizontal: t.space.md,
      marginLeft: -t.space.sm,
      borderRadius: t.radius.pill,
    },
    backPressed: { backgroundColor: t.c.hover },
    backText: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.medium },
    headerTitles: { flex: 1, minWidth: 0, gap: t.space.xxs },
    title: { color: t.c.text, ...type(t, "xl"), fontWeight: t.font.weight.semibold, letterSpacing: -0.2 },
    subtitle: { color: t.c.textMuted, ...type(t, "sm") },
    headerActions: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    body: { padding: t.space.lg, paddingBottom: t.space.xxxl, gap: t.space.lg, width: "100%", maxWidth: 720, alignSelf: "center" },
    bodyWide: { maxWidth: 1080 },

    card: {
      backgroundColor: t.c.raised,
      borderRadius: t.radius.lg,
      borderWidth: hairline,
      borderColor: t.c.border,
      padding: t.space.lg,
      gap: t.space.md,
      boxShadow: t.shadow.card,
    },
    cardTitle: { color: t.c.text, ...type(t, "lg"), fontWeight: t.font.weight.semibold },
    /** A group heading above a card, as in the sidebar. */
    section: {
      color: t.c.textMuted,
      ...type(t, "xs"),
      fontWeight: t.font.weight.semibold,
      textTransform: "uppercase",
      letterSpacing: 0.6,
      marginTop: t.space.sm,
      marginBottom: -t.space.sm,
      paddingHorizontal: t.space.xs,
    },
    /** A titled part inside a card, set off by a hairline. */
    field: { gap: t.space.sm, paddingTop: t.space.md, borderTopWidth: hairline, borderTopColor: t.c.border },
    /** A row of a list inside a card. */
    row: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      paddingVertical: t.space.md,
      borderTopWidth: hairline,
      borderTopColor: t.c.border,
    },
    rowFirst: { borderTopWidth: 0 },
    actions: { flexDirection: "row", flexWrap: "wrap", alignItems: "center", gap: t.space.sm },

    text: { color: t.c.text, ...type(t, "md") },
    strong: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.semibold },
    label: { color: t.c.text, ...type(t, "sm"), fontWeight: t.font.weight.medium },
    dim: { color: t.c.textMuted, ...type(t, "sm") },
    faint: { color: t.c.textFaint, ...type(t, "xs") },
    link: { color: t.c.accentText, ...type(t, "md") },
    mono: { color: t.c.text, fontFamily: t.font.mono, ...type(t, "sm") },
    error: { color: t.c.danger, ...type(t, "sm") },
    good: { color: t.c.success, ...type(t, "sm") },
    warn: { color: t.c.warning, ...type(t, "sm") },
    empty: { color: t.c.textFaint, ...type(t, "sm"), padding: t.space.lg, textAlign: "center" },

    /** Tinted boxes for messages that need to stand out. */
    noticeError: { backgroundColor: t.c.dangerSoft, borderRadius: t.radius.md, padding: t.space.md, gap: t.space.sm },
    noticeWarn: { backgroundColor: t.c.warningSoft, borderRadius: t.radius.md, padding: t.space.md, gap: t.space.sm },
    noticeGood: { backgroundColor: t.c.successSoft, borderRadius: t.radius.md, padding: t.space.md, gap: t.space.sm },
    noticeInfo: { backgroundColor: t.c.accentSoft, borderRadius: t.radius.md, padding: t.space.md, gap: t.space.sm },
    inset: { backgroundColor: t.c.codeBg, borderRadius: t.radius.md, padding: t.space.md, gap: t.space.sm },

    input: {
      backgroundColor: t.c.bg,
      borderRadius: t.radius.md,
      borderWidth: 1,
      borderColor: t.c.border,
      paddingHorizontal: t.space.md,
      paddingVertical: 10,
      color: t.c.text,
      ...type(t, "md"),
    },
    inputMultiline: { minHeight: 88, textAlignVertical: "top" },
    search: {
      backgroundColor: t.c.raised,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.border,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.sm,
      color: t.c.text,
      ...type(t, "md"),
    },

    btn: {
      alignItems: "center",
      justifyContent: "center",
      flexDirection: "row",
      gap: t.space.xs,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.borderStrong,
      backgroundColor: t.c.raised,
      paddingVertical: t.space.sm,
      paddingHorizontal: t.space.lg,
    },
    btnSmall: { paddingVertical: t.space.xs, paddingHorizontal: t.space.md },
    btnPressed: { backgroundColor: t.c.hover },
    btnText: { color: t.c.text, ...type(t, "sm"), fontWeight: t.font.weight.medium },
    primary: { backgroundColor: t.c.accent, borderColor: t.c.accent },
    primaryText: { color: t.c.onAccent, fontWeight: t.font.weight.semibold },
    danger: { backgroundColor: t.c.dangerSoft, borderColor: t.c.dangerSoft },
    dangerText: { color: t.c.danger, fontWeight: t.font.weight.semibold },
    ghost: { backgroundColor: "transparent", borderColor: "transparent" },
    ghostText: { color: t.c.accentText },
    disabled: { opacity: 0.5 },

    tag: {
      color: t.c.textMuted,
      ...type(t, "xs"),
      backgroundColor: t.c.selected,
      borderRadius: t.radius.pill,
      paddingHorizontal: t.space.sm,
      paddingVertical: t.space.xxs,
      overflow: "hidden",
    },
    tagAccent: { color: t.c.accentText, backgroundColor: t.c.accentSoft },
    tagDanger: { color: t.c.danger, backgroundColor: t.c.dangerSoft },
    tagWarn: { color: t.c.warning, backgroundColor: t.c.warningSoft },
    tagGood: { color: t.c.success, backgroundColor: t.c.successSoft },
    tags: { flexDirection: "row", flexWrap: "wrap", gap: t.space.xs },

    backdrop: { flex: 1, backgroundColor: t.c.overlay, justifyContent: "center", padding: t.space.lg },
    sheet: {
      flexGrow: 0,
      maxHeight: "90%",
      width: "100%",
      maxWidth: 560,
      alignSelf: "center",
      backgroundColor: t.c.elevated,
      borderRadius: t.radius.xl,
      borderWidth: hairline,
      borderColor: t.c.border,
      boxShadow: t.shadow.pop,
    },
    sheetBody: { padding: t.space.xl, gap: t.space.md },
  });

/**
 * The shared look of the settings and admin screens (ADR 0337), on the design tokens (ADR 0335).
 * A screen's own `themedStyles` picks from `kit(t)` under its own names, so every screen agrees.
 */
export const useUi = themedStyles(build);

const kits: Partial<Record<Theme["scheme"], ReturnType<typeof build>>> = {};
export function kit(t: Theme): ReturnType<typeof build> {
  return (kits[t.scheme] ??= build(t));
}

interface HeaderProps {
  /** Left out where the content below names itself, as in a detail sheet. */
  title?: string;
  /** A quiet line under the title. */
  subtitle?: string;
  onBack?: () => void;
  backText?: string;
  backLabel?: string;
  /** Holds the back button, e.g. while a request that returns a one-time secret runs. */
  backDisabled?: boolean;
  right?: React.ReactNode;
}

/**
 * Every screen's top bar (ADR 0340): a back pill named for where it goes, the title as the
 * screen's header, and its actions on the right.
 */
export function PageHeader({ title, subtitle, onBack, backText = "‹ Bots", backLabel = "Back to Bots", backDisabled, right }: HeaderProps) {
  const ui = useUi();
  return (
    <View style={ui.header}>
      {onBack ? <BackButton onPress={onBack} text={backText} label={backLabel} disabled={backDisabled} /> : null}
      <View style={ui.headerTitles}>
        {title ? (
          <Text style={ui.title} accessibilityRole="header" numberOfLines={1}>
            {title}
          </Text>
        ) : null}
        {subtitle ? (
          <Text style={ui.subtitle} numberOfLines={1}>
            {subtitle}
          </Text>
        ) : null}
      </View>
      {right ? <View style={ui.headerActions}>{right}</View> : null}
    </View>
  );
}

/** A header's back pill. Without a `label`, screen readers read its text. */
export function BackButton({ onPress, text, label, disabled }: { onPress: () => void; text: string; label?: string; disabled?: boolean }) {
  const ui = useUi();
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      accessibilityState={disabled === undefined ? undefined : { disabled }}
      accessibilityRole="button"
      accessibilityLabel={label}
      hitSlop={8}
      style={({ pressed }) => [ui.back, pressed && ui.backPressed, disabled && ui.disabled]}
    >
      <Text style={ui.backText} numberOfLines={1}>
        {text}
      </Text>
    </Pressable>
  );
}

/** A rounded card, with an optional title. */
export function Card({
  title,
  children,
  style,
  accessibilityLabel,
  testID,
}: {
  title?: string;
  children?: React.ReactNode;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
  testID?: string;
}) {
  const ui = useUi();
  return (
    <View style={[ui.card, style]} accessibilityLabel={accessibilityLabel} testID={testID}>
      {title ? (
        <Text style={ui.cardTitle} role="heading">
          {title}
        </Text>
      ) : null}
      {children}
    </View>
  );
}

interface PillButtonProps {
  label: string;
  onPress: () => void;
  /** Primary fills with the accent; use it for the one next step on a screen. */
  tone?: "primary" | "secondary";
  /** Disables the button and shows `busyLabel` while the action runs. */
  busy?: boolean;
  busyLabel?: string;
  disabled?: boolean;
  hint?: string;
  small?: boolean;
}

/** The kit's pill button as a component, for empty and error states, toasts and banners (ADR 0339). */
export function PillButton({ label, onPress, tone = "secondary", busy, busyLabel, disabled, hint, small }: PillButtonProps) {
  const ui = useUi();
  const off = !!(disabled || busy);
  const text = busy && busyLabel ? busyLabel : label;
  return (
    <Pressable
      role="button"
      aria-label={text}
      aria-disabled={off}
      aria-busy={!!busy}
      accessibilityHint={hint}
      disabled={off}
      hitSlop={small ? 8 : 4}
      onPress={onPress}
      style={({ pressed }) => [
        ui.btn,
        { minHeight: small ? 32 : 40 },
        small && ui.btnSmall,
        tone === "primary" && ui.primary,
        pressed && (tone === "primary" ? { opacity: 0.7 } : ui.btnPressed),
        off && ui.disabled,
      ]}
    >
      <Text style={[ui.btnText, tone === "primary" && ui.primaryText]}>{text}</Text>
    </Pressable>
  );
}

/** The placeholder colour for text fields. */
export function usePlaceholder(): string {
  return useTheme().c.textFaint;
}
