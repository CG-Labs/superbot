import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { isStarter } from "../src/prompts";
import { colors } from "../src/theme";

interface Props {
  botName: string;
  prompts: string[];
  /** Sends the prompt, or puts a starter in the message box. */
  onUse: (prompt: string) => void;
  /** For those who manage the Bot. */
  onEdit?: () => void;
}

/** A Bot's suggested prompts in its details (ADR 0054). Only for those who can run it. */
export function SuggestedPrompts({ botName, prompts, onUse, onEdit }: Props) {
  if (!prompts.length && !onEdit) return null;
  return (
    <View style={styles.wrap}>
      <View style={styles.header}>
        <Text style={styles.label} role="heading">
          Suggested
        </Text>
        {onEdit ? (
          <Pressable role="button" aria-label="Edit suggested prompts" hitSlop={8} onPress={onEdit}>
            <Text style={styles.link}>Edit</Text>
          </Pressable>
        ) : null}
      </View>
      {prompts.length ? (
        <View style={styles.card} role="list">
          {prompts.map((p, i) => {
            const starter = isStarter(p);
            return (
              <Pressable
                key={p}
                role="button"
                aria-label={starter ? `Start a message: ${p}` : `Ask ${botName}: ${p}`}
                accessibilityHint={starter ? "Puts it in the message box to finish" : "Sends it now"}
                style={({ pressed }) => [styles.item, i > 0 && styles.divider, pressed && styles.pressed]}
                onPress={() => onUse(p)}
              >
                <Text style={styles.icon} aria-hidden>
                  {starter ? "✎" : "↗"}
                </Text>
                <Text style={styles.text}>{p}</Text>
                <Text style={styles.chevron} aria-hidden>
                  ›
                </Text>
              </Pressable>
            );
          })}
        </View>
      ) : (
        <Text style={styles.dim}>No suggested prompts</Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { width: "100%", gap: 6, marginTop: 8 },
  header: { flexDirection: "row", alignItems: "center" },
  label: { color: colors.textFaint, flex: 1 },
  link: { color: colors.blueDot },
  card: {
    backgroundColor: colors.bgBubble,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    overflow: "hidden",
  },
  item: { flexDirection: "row", alignItems: "center", gap: 10, paddingHorizontal: 12, paddingVertical: 12, minHeight: 44 },
  divider: { borderTopWidth: 1, borderTopColor: colors.border },
  pressed: { backgroundColor: colors.bgActive },
  icon: { color: colors.blueDot, width: 18, textAlign: "center" },
  text: { color: colors.text, flex: 1 },
  chevron: { color: colors.textFaint, fontSize: 18 },
  dim: { color: colors.textDim },
});
