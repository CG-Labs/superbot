import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { colors } from "../src/theme";
import type { Message } from "../src/types";

interface Props {
  botName: string;
  handoff: Message;
  onOpenScreen: () => void;
}

/** Pinned above the chat while a Bot waits for the user on its screen (`botctl handoff`). */
export function HandoffBanner({ botName, handoff, onOpenScreen }: Props) {
  return (
    <View style={styles.banner} aria-live="polite">
      <View style={styles.text}>
        <Text style={styles.label}>{botName} needs you on its screen</Text>
        <Text style={styles.title} numberOfLines={2}>
          {handoff.question?.title}
        </Text>
      </View>
      <Pressable role="button" aria-label="Open screen" style={styles.btn} onPress={onOpenScreen}>
        <Text style={styles.btnText}>Open screen</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  banner: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    marginHorizontal: 12,
    marginTop: 10,
    padding: 12,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.blue,
    backgroundColor: "#16223a",
  },
  text: { flex: 1, gap: 2 },
  label: { color: colors.textDim, fontSize: 13 },
  title: { color: colors.text, fontWeight: "600" },
  btn: { backgroundColor: colors.blue, borderRadius: 999, paddingHorizontal: 14, paddingVertical: 8 },
  btnText: { color: "#fff", fontWeight: "600" },
});
