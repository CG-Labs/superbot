import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { themedStyles, type } from "../src/theme";

interface Props<T extends string | number> {
  options: readonly { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  disabled?: boolean;
}

/** A row of choices, one picked. */
export function Chips<T extends string | number>({ options, value, onChange, disabled }: Props<T>) {
  const styles = useStyles();
  return (
    <View style={styles.row} accessibilityRole="radiogroup">
      {options.map((o) => {
        const on = o.value === value;
        return (
          <Pressable
            key={String(o.value)}
            accessibilityRole="radio"
            accessibilityState={{ checked: on, disabled }}
            style={({ pressed }) => [styles.chip, pressed && !on && styles.pressed, on && styles.on, disabled && styles.disabled]}
            disabled={disabled}
            onPress={() => onChange(o.value)}
          >
            <Text style={[styles.text, on && styles.onText]}>{o.label}</Text>
          </Pressable>
        );
      })}
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    row: { flexDirection: "row", flexWrap: "wrap", gap: t.space.sm },
    chip: {
      paddingVertical: 6,
      paddingHorizontal: 14,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.border,
      backgroundColor: t.c.raised,
    },
    pressed: { backgroundColor: t.c.hover },
    on: { backgroundColor: t.c.text, borderColor: t.c.text },
    disabled: { opacity: 0.5 },
    text: { color: t.c.text, ...type(t, "sm") },
    onText: { color: t.c.bg, fontWeight: t.font.weight.medium },
  }),
);
