import React from "react";
import { Pressable, StyleSheet, Text } from "react-native";
import { themedStyles, type } from "../src/theme";

interface Props {
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

/** The design system's rounded button, for empty and error states, toasts and banners. */
export function PillButton({ label, onPress, tone = "secondary", busy, busyLabel, disabled, hint, small }: Props) {
  const styles = useStyles();
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
        styles.btn,
        small && styles.small,
        tone === "primary" ? styles.primary : styles.secondary,
        pressed && styles.pressed,
        off && styles.off,
      ]}
    >
      <Text style={[small ? styles.textSmall : styles.text, tone === "primary" ? styles.primaryText : styles.secondaryText]}>{text}</Text>
    </Pressable>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    btn: {
      minHeight: 40,
      paddingHorizontal: t.space.lg + 2,
      paddingVertical: t.space.sm,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      alignItems: "center",
      justifyContent: "center",
    },
    small: { minHeight: 32, paddingHorizontal: t.space.md, paddingVertical: t.space.xs },
    primary: { backgroundColor: t.c.accent, borderColor: t.c.accent },
    secondary: { backgroundColor: t.c.raised, borderColor: t.c.borderStrong },
    pressed: { opacity: 0.7 },
    off: { opacity: 0.55 },
    text: { ...type(t, "md"), fontWeight: t.font.weight.semibold },
    textSmall: { ...type(t, "sm"), fontWeight: t.font.weight.semibold },
    primaryText: { color: t.c.onAccent },
    secondaryText: { color: t.c.text },
  }),
);
