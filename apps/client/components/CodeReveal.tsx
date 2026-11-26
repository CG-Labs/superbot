import React, { useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { COPY_LABEL, copyText } from "../src/clipboard";
import { formatExpiry, inviteLink, inviteMessage } from "../src/invite";
import { themedStyles, type } from "../src/theme";
import type { LoginCode } from "../src/types";
import { kit } from "./ui";

interface Props {
  code: LoginCode;
  name: string;
  serverUrl: string;
  onDone: () => void;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const styles = useStyles();
  const [done, setDone] = useState<boolean | null>(null);
  return (
    <Pressable style={({ pressed }) => [styles.copy, pressed && styles.pressed]} onPress={() => void copyText(text).then(setDone)}>
      <Text style={styles.copyText}>{done ? "Copied" : done === false ? "Select and copy it" : `${COPY_LABEL} ${label}`}</Text>
    </Pressable>
  );
}

/**
 * A new sign-in code, shown this once. The server keeps only its hash, so closing this
 * is the end of it: making another code is the only way to get one.
 */
export function CodeReveal({ code, name, serverUrl, onDone }: Props) {
  const styles = useStyles();
  const message = inviteMessage({ name, serverUrl, code: code.code, expiresAt: code.expiresAt });
  const link = inviteLink(serverUrl, code.code);
  return (
    <View style={styles.wrap} testID="code-reveal">
      <View style={styles.notice}>
        <Text style={styles.warn}>Copy it now. This code is shown once and can't be shown again.</Text>
      </View>
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    wrap: { gap: t.space.md },
    notice: k.noticeWarn,
    warn: { ...k.warn, fontWeight: t.font.weight.semibold },
    code: { ...k.inset, ...k.mono, ...type(t, "lg"), letterSpacing: 1 },
    dim: k.dim,
    label: { ...k.label, marginTop: t.space.xs },
    message: { ...k.inset, ...k.text, ...type(t, "sm") },
    row: k.actions,
    copy: { ...k.btn, ...k.btnSmall },
    copyText: k.btnText,
    pressed: k.btnPressed,
    done: { ...k.btn, ...k.primary, alignSelf: "flex-end" },
    doneText: { ...k.btnText, ...k.primaryText },
  });
});
