import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { colors } from "../src/theme";

interface Props<T extends string | number> {
  options: readonly { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  disabled?: boolean;
}

/** A row of choices, one picked. */
export function Chips<T extends string | number>({ options, value, onChange, disabled }: Props<T>) {
  return (
    <View style={styles.row} accessibilityRole="radiogroup">
      {options.map((o) => {
        const on = o.value === value;
        return (
          <Pressable
            key={String(o.value)}
            accessibilityRole="radio"
            accessibilityState={{ checked: on, disabled }}
            style={[styles.chip, on && styles.on, disabled && styles.disabled]}
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

const styles = StyleSheet.create({
  row: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  chip: { paddingVertical: 7, paddingHorizontal: 14, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a" },
  on: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  disabled: { opacity: 0.5 },
  text: { color: colors.text, fontSize: 14 },
  onText: { color: "#111" },
});
