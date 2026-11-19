import React, { useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { COPY_LABEL, copyText } from "../src/clipboard";
import { formatExpiry, inviteLink, inviteMessage } from "../src/invite";
import { colors } from "../src/theme";
import type { LoginCode } from "../src/types";

interface Props {
  code: LoginCode;
  name: string;
  serverUrl: string;
  onDone: () => void;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState<boolean | null>(null);
  return (
    <Pressable style={styles.copy} onPress={() => void copyText(text).then(setDone)}>
      <Text style={styles.copyText}>{done ? "Copied" : done === false ? "Select and copy it" : `${COPY_LABEL} ${label}`}</Text>
    </Pressable>
  );
}

/**
 * A new sign-in code, shown this once. The server keeps only its hash, so closing this
 * is the end of it: making another code is the only way to get one.
 */
export function CodeReveal({ code, name, serverUrl, onDone }: Props) {
  const message = inviteMessage({ name, serverUrl, code: code.code, expiresAt: code.expiresAt });
  const link = inviteLink(serverUrl, code.code);
  return (
    <View style={styles.wrap} testID="code-reveal">
      <Text style={styles.warn}>Copy it now. This code is shown once and can't be shown again.</Text>
      <Text style={styles.code} selectable testID="code-value">
        {code.code}
      </Text>
      <Text style={styles.dim}>One use, expires {formatExpiry(code.expiresAt)}.</Text>
      <View style={styles.row}>
        <CopyButton text={code.code} label="code" />
        <CopyButton text={link} label="link" />
        <CopyButton text={message} label="invite" />
      </View>
      <Text style={styles.label}>Invite message</Text>
      <Text style={styles.message} selectable>
        {message}
      </Text>
      <Pressable style={styles.done} onPress={onDone}>
        <Text style={styles.doneText}>Done</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { gap: 10, backgroundColor: colors.bgBubble, borderRadius: 14, padding: 14, borderWidth: 1, borderColor: "#2d4a33" },
  warn: { color: colors.warning, fontWeight: "600" },
  code: { color: colors.text, fontFamily: "monospace", fontSize: 13, backgroundColor: "#151515", borderRadius: 10, padding: 10 },
  dim: { color: colors.textDim, fontSize: 13 },
  label: { color: colors.textDim, fontSize: 13, marginTop: 4 },
  message: { color: colors.text, fontSize: 13, backgroundColor: "#151515", borderRadius: 10, padding: 10, lineHeight: 19 },
  row: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  copy: { paddingVertical: 7, paddingHorizontal: 14, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a" },
  copyText: { color: colors.text, fontSize: 14 },
  done: { alignSelf: "flex-end", paddingVertical: 8, paddingHorizontal: 18, borderRadius: 999, backgroundColor: "#f2f2f2" },
  doneText: { color: "#111", fontSize: 15 },
});
