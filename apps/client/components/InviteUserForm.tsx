import React, { useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Switch, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { CODE_TTLS, ROLES } from "../src/invite";
import { themedStyles, useTheme } from "../src/theme";
import type { AdminUser, LoginCode, Role } from "../src/types";
import { Chips } from "./Chips";
import { CodeReveal } from "./CodeReveal";
import { kit, usePlaceholder } from "./ui";

interface Props {
  api: SuperBotApi;
  onCreated: (u: AdminUser) => void;
  onClose: () => void;
  /** While the user and code are being made: the sheet must stay open, or the code is lost. */
  onBusy?: (busy: boolean) => void;
}

export function InviteUserForm({ api, onCreated, onClose, onBusy }: Props) {
  const styles = useStyles();
  const t = useTheme();
  const placeholder = usePlaceholder();
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
        placeholderTextColor={placeholder}
        value={email}
        onChangeText={setEmail}
        accessibilityLabel="Email"
      />
      <Text style={styles.label}>Name</Text>
      <TextInput
        style={styles.input}
        placeholder="Alex Smith (optional)"
        placeholderTextColor={placeholder}
        value={name}
        onChangeText={setName}
        accessibilityLabel="Name"
      />
      <Text style={styles.label}>Role</Text>
      <Chips options={ROLES.map((r) => ({ value: r.role, label: r.label }))} value={role} onChange={setRole} />
      {roleHint ? <Text style={styles.hint}>{roleHint}</Text> : null}
      <View style={styles.switchRow}>
        <Switch value={withCode} onValueChange={setWithCode} trackColor={{ false: t.c.borderStrong, true: t.c.accent }} accessibilityLabel="Make a sign-in code" />
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
        <Pressable style={({ pressed }) => [styles.btn, pressed && styles.pressed, busy && styles.disabled]} disabled={busy} onPress={onClose}>
          <Text style={styles.btnText}>Cancel</Text>
        </Pressable>
        <Pressable style={[styles.btn, styles.primary, (busy || !email.trim()) && styles.disabled]} disabled={busy || !email.trim()} onPress={() => void submit()}>
          {busy ? <ActivityIndicator color={t.c.onAccent} /> : <Text style={[styles.btnText, styles.primaryText]}>Add user</Text>}
        </Pressable>
      </View>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    form: { gap: t.space.sm },
    label: { ...k.label, marginTop: t.space.xs },
    input: k.input,
    hint: k.faint,
    text: { ...k.text, flex: 1 },
    switchRow: { flexDirection: "row", alignItems: "center", gap: t.space.md, marginTop: t.space.sm },
    error: k.error,
    actions: { ...k.actions, justifyContent: "flex-end", marginTop: t.space.md },
    btn: { ...k.btn, minWidth: 90 },
    btnText: k.btnText,
    pressed: k.btnPressed,
    primary: k.primary,
    primaryText: k.primaryText,
    disabled: k.disabled,
  });
});
