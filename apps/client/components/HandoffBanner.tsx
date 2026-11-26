import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { themedStyles, type } from "../src/theme";
import type { Message } from "../src/types";

interface Props {
  botName: string;
  handoff: Message;
  onOpenScreen: () => void;
}

/** Pinned above the chat while a Bot waits for the user on its screen (`botctl handoff`). */
export function HandoffBanner({ botName, handoff, onOpenScreen }: Props) {
  const styles = useStyles();
  return (
    <View style={styles.banner} aria-live="polite">
      <View style={styles.text}>
        <Text style={styles.label}>{botName} needs you on its screen</Text>
        <Text style={styles.title} numberOfLines={2}>
          {handoff.question?.title}
        </Text>
      </View>
      <Pressable role="button" aria-label="Open screen" style={({ pressed }) => [styles.btn, pressed && styles.pressed]} onPress={onOpenScreen}>
        <Text style={styles.btnText}>Open screen</Text>
      </Pressable>
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    banner: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      marginHorizontal: t.space.lg,
      marginTop: t.space.md,
      paddingVertical: t.space.md,
      paddingHorizontal: t.space.lg,
      borderRadius: t.radius.lg,
      borderWidth: 1,
      borderColor: t.c.accentBorder,
      backgroundColor: t.c.accentSoft,
    },
    text: { flex: 1, gap: t.space.xxs },
    label: { color: t.c.accentText, ...type(t, "sm"), fontWeight: t.font.weight.medium },
    title: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.semibold },
    btn: { backgroundColor: t.c.accent, borderRadius: t.radius.pill, paddingHorizontal: t.space.lg, paddingVertical: t.space.sm },
    btnText: { color: t.c.onAccent, fontWeight: t.font.weight.semibold },
    pressed: { opacity: 0.7 },
  }),
);
