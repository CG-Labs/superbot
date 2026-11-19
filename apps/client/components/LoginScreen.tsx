import React, { useState } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { defaultServerUrl } from "../src/auth";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

export function LoginScreen() {
  const { login, error: bootError } = useSuperBot();
  const [baseUrl, setBaseUrl] = useState(() => defaultServerUrl());
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async () => {
    setBusy(true);
    setError(null);
    try {
      await login(baseUrl, secret);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.wrap}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <View style={styles.card}>
        <Text style={styles.title}>SuperBot</Text>
        <Text style={styles.sub}>Connect to your self-hosted server</Text>
        <Text style={styles.label}>Server URL</Text>
        <TextInput
          style={styles.input}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          placeholder="https://your-server:3000"
          placeholderTextColor={colors.textFaint}
          value={baseUrl}
          onChangeText={setBaseUrl}
        />
        <Text style={styles.label}>Sign-in code or password</Text>
        <TextInput
          style={styles.input}
          secureTextEntry
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="sbc_… or AUTH_PASSWORD"
          placeholderTextColor={colors.textFaint}
          value={secret}
          onChangeText={setSecret}
        />
        <Text style={styles.hint}>
          Ask an admin for a one-time sign-in code. The owner can use the server password. The app keeps a session token, not the password.
        </Text>
        {(error || bootError) ? (
          <Text style={styles.error}>{error || bootError}</Text>
        ) : null}
        <Pressable style={[styles.btn, busy && styles.btnDisabled]} onPress={onSubmit} disabled={busy}>
          {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Connect</Text>}
        </Pressable>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  wrap: {
    flex: 1,
    backgroundColor: colors.bgMain,
    justifyContent: "center",
    padding: 24,
  },
  card: {
    maxWidth: 440,
    width: "100%",
    alignSelf: "center",
    gap: 8,
  },
  title: { fontSize: 32, fontWeight: "700", color: colors.text },
  sub: { color: colors.textDim, marginBottom: 16 },
  label: { color: colors.textDim, fontSize: 14, marginTop: 8 },
  input: {
    backgroundColor: colors.bgBubble,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: Platform.OS === "web" ? 12 : 14,
    color: colors.text,
    fontSize: 16,
  },
  hint: { color: colors.textFaint, fontSize: 13, lineHeight: 18 },
  error: { color: colors.danger, marginTop: 4 },
  btn: {
    marginTop: 16,
    backgroundColor: colors.blue,
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
  },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: "#fff", fontWeight: "600", fontSize: 16 },
});