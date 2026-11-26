import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { isStarter } from "../src/prompts";
import { hairline, themedStyles, type } from "../src/theme";
import { EmptyState } from "./EmptyState";
import { kit } from "./ui";

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
  const styles = useStyles();
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
        <EmptyState compact glyph="+" title="No suggested prompts" message="Add a few so people can start a chat with one tap." />
      )}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    wrap: { width: "100%", gap: t.space.xs, marginTop: t.space.sm },
    header: { flexDirection: "row", alignItems: "center" },
    label: { color: t.c.textMuted, ...type(t, "sm"), fontWeight: t.font.weight.semibold, flex: 1 },
    link: k.link,
    card: {
      backgroundColor: t.c.raised,
      borderRadius: t.radius.md,
      borderWidth: hairline,
      borderColor: t.c.border,
      overflow: "hidden",
    },
    item: { flexDirection: "row", alignItems: "center", gap: t.space.sm, paddingHorizontal: t.space.md, paddingVertical: t.space.md, minHeight: 44 },
    divider: { borderTopWidth: hairline, borderTopColor: t.c.border },
    pressed: { backgroundColor: t.c.hover },
    icon: { color: t.c.accentText, width: 18, textAlign: "center" },
    text: { ...k.text, flex: 1 },
    chevron: { color: t.c.textFaint, fontSize: 18 },
  });
});
