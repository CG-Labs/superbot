import React, { useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Switch, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { CODE_TTLS, ROLES } from "../src/invite";
import { colors } from "../src/theme";
import type { AdminUser, LoginCode, Role } from "../src/types";
import { Chips } from "./Chips";
import { CodeReveal } from "./CodeReveal";

interface Props {
  api: SuperBotApi;
  onCreated: (u: AdminUser) => void;
  onClose: () => void;
  /** While the user and code are being made: the sheet must stay open, or the code is lost. */
  onBusy?: (busy: boolean) => void;
}

export function InviteUserForm({ api, onCreated, onClose, onBusy }: Props) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [withCode, setWithCode] = useState(true);
  const [ttl, setTtl] = useState<number>(CODE_TTLS[1].minutes);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [made, setMade] = useState<{ user: AdminUser; code: LoginCode } | null>(null);
  useEffect(() => onBusy?.(busy), [busy, onBusy]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    let user: AdminUser | null = null;
    try {
      user = await api.createUser({ email: email.trim(), name: name.trim() || undefined, role });
      onCreated(user);
      if (!withCode) return onClose();
      setMade({ user, code: await api.createLoginCode(user.id, ttl) });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed";
      setError(user ? `${user.name} was added, but no code was made: ${msg}. Make one from their page.` : msg);
    } finally {
      setBusy(false);
    }
  };

  if (made) {
    return <CodeReveal code={made.code} name={made.user.name} serverUrl={api.baseUrl} onDone={onClose} />;
  }

  const roleHint = ROLES.find((r) => r.role === role)?.hint;
  return (
    <View style={styles.form}>
      <Text style={styles.label}>Email</Text>
      <TextInput
        style={styles.input}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="email-address"
        placeholder="alex@example.com"
        placeholderTextColor={colors.textFaint}
        value={email}
        onChangeText={setEmail}
        accessibilityLabel="Email"
      />
      <Text style={styles.label}>Name</Text>
      <TextInput
        style={styles.input}
        placeholder="Alex Smith (optional)"
        placeholderTextColor={colors.textFaint}
        value={name}
        onChangeText={setName}
        accessibilityLabel="Name"
      />
      <Text style={styles.label}>Role</Text>
      <Chips options={ROLES.map((r) => ({ value: r.role, label: r.label }))} value={role} onChange={setRole} />
      {roleHint ? <Text style={styles.hint}>{roleHint}</Text> : null}
      <View style={styles.switchRow}>
        <Switch value={withCode} onValueChange={setWithCode} accessibilityLabel="Make a sign-in code" />
        <Text style={styles.text}>Make a one-time sign-in code</Text>
      </View>
      {withCode ? (
        <>
          <Text style={styles.label}>Code expires after</Text>
          <Chips options={CODE_TTLS.map((t) => ({ value: t.minutes, label: t.label }))} value={ttl} onChange={setTtl} />
        </>
      ) : (
        <Text style={styles.hint}>They can sign in with SSO once you link their account, or you can make a code later.</Text>
      )}
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <View style={styles.actions}>
        <Pressable style={[styles.btn, busy && styles.disabled]} disabled={busy} onPress={onClose}>
          <Text style={styles.btnText}>Cancel</Text>
        </Pressable>
        <Pressable style={[styles.btn, styles.primary, (busy || !email.trim()) && styles.disabled]} disabled={busy || !email.trim()} onPress={() => void submit()}>
          {busy ? <ActivityIndicator color="#111" /> : <Text style={[styles.btnText, styles.primaryText]}>Add user</Text>}
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  form: { gap: 8 },
  label: { color: colors.textDim, fontSize: 14, marginTop: 6 },
  input: {
    backgroundColor: colors.bgBubble,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: colors.text,
    fontSize: 16,
  },
  hint: { color: colors.textFaint, fontSize: 13 },
  text: { color: colors.text },
  switchRow: { flexDirection: "row", alignItems: "center", gap: 10, marginTop: 10 },
  error: { color: colors.danger },
  actions: { flexDirection: "row", justifyContent: "flex-end", gap: 10, marginTop: 12 },
  btn: { paddingVertical: 9, paddingHorizontal: 18, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a", minWidth: 90, alignItems: "center" },
  btnText: { color: colors.text, fontSize: 15 },
  primary: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  primaryText: { color: "#111" },
  disabled: { opacity: 0.5 },
});
