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
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

export function LoginScreen() {
  const { login, error: bootError } = useSuperBot();
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:3000");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async () => {
    setBusy(true);
    setError(null);
    try {
      await login(baseUrl, password);
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
        <Text style={styles.label}>Password (AUTH_PASSWORD)</Text>
        <TextInput
          style={styles.input}
          secureTextEntry
          placeholder="Required"
          placeholderTextColor={colors.textFaint}
          value={password}
          onChangeText={setPassword}
        />
        <Text style={styles.hint}>
          The client always sends HTTP Basic auth. Set AUTH_PASSWORD on botd for remote access.
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