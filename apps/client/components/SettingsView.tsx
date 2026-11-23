import React, { useState } from "react";
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { availabilityProblem, LOCK_AFTER_OPTIONS, lockAfterLabel } from "../src/appLock";
import { colors } from "../src/theme";
import { useAppLock } from "./AppLock";
import { Chips } from "./Chips";
import { PushCard, type PushApi } from "./PushCard";
import { ResidencyCard, type ResidencyApi } from "./ResidencyCard";
import { TwoFactorCard, type MfaApi } from "./TwoFactor";

interface Props {
  onBack: () => void;
  /** The signed-in server, for this phone's push notifications (ADR 0080), your second factor (ADR 0094) and your data's residency pin (ADR 0166). */
  api?: PushApi & MfaApi & ResidencyApi;
  /** Admins also set who must use two-factor authentication. */
  admin?: boolean;
}

/** This device's own settings: App lock is kept on the device, push on the server for this session. */
export function SettingsView({ onBack, api, admin = false }: Props) {
  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
          <Text style={styles.back}>‹ Bots</Text>
        </Pressable>
        <Text style={styles.title}>Settings</Text>
      </View>
      <ScrollView contentContainerStyle={styles.body}>
        <AppLockCard />
        {api ? <PushCard api={api} /> : null}
        {api ? <TwoFactorCard api={api} admin={admin} /> : null}
        {api ? <ResidencyCard api={api} /> : null}
      </ScrollView>
    </View>
  );
}

/** App lock (ADR 0078): off by default, and unavailable where there are no biometrics. */
export function AppLockCard() {
  const { settings, availability, enable, disable, setLockAfter } = useAppLock();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const run = async (fn: () => Promise<string | null | void>, done: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const problem = await fn();
      if (problem) setError(problem);
      else setNotice(done);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!availability) {
    return (
      <View style={styles.card} accessibilityLabel="App lock">
        <Text style={styles.cardTitle}>App lock</Text>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }

  const problem = availabilityProblem(availability);
  if (availability.kind === "unsupported") {
    return (
      <View style={styles.card} accessibilityLabel="App lock">
        <Text style={styles.cardTitle}>App lock</Text>
        <Text style={styles.dim}>{problem}</Text>
      </View>
    );
  }

  const label = availability.kind === "available" || availability.kind === "not-enrolled" ? availability.label : "biometrics";
  return (
    <View style={styles.card} accessibilityLabel="App lock">
      <Text style={styles.cardTitle}>App lock</Text>
      <Text style={styles.dim}>
        Ask for {label} or your device passcode when SuperBot opens, and hide your chats in the app switcher. This is kept on this device only; signing out turns it off.
      </Text>
      {notice ? (
        <Text style={styles.good} accessibilityRole="alert">
          {notice}
        </Text>
      ) : null}
      {error ? (
        <Text style={styles.error} accessibilityRole="alert">
          {error}
        </Text>
      ) : null}
      {problem ? <Text style={styles.warn}>{settings.enabled ? `${problem} Until then, SuperBot asks for your device passcode, or for you to sign out if it has none.` : problem}</Text> : null}
      <View style={styles.field} accessibilityLabel="App lock on or off">
        <Text style={styles.label}>App lock</Text>
        <Chips
          options={[
            { value: "on", label: "On" },
            { value: "off", label: "Off" },
          ]}
          value={settings.enabled ? "on" : "off"}
          onChange={(v) => {
            if (v === "on" && !settings.enabled) void run(enable, "App lock is on.");
            if (v === "off" && settings.enabled) void run(disable, "App lock is off.");
          }}
          disabled={busy || (!settings.enabled && !!problem)}
        />
      </View>
      {settings.enabled ? (
        <View style={styles.field} accessibilityLabel="Lock after">
          <Text style={styles.label}>Lock again after leaving the app</Text>
          <Chips options={LOCK_AFTER_OPTIONS} value={settings.lockAfter} onChange={(v) => void run(() => setLockAfter(v), `Locks ${lockAfterLabel(v).toLowerCase()}.`)} disabled={busy} />
        </View>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  header: { flexDirection: "row", alignItems: "center", gap: 16, padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border },
  back: { color: colors.blueDot, fontSize: 16 },
  title: { color: colors.text, fontSize: 20, fontWeight: "600", flex: 1 },
  body: { padding: 16, gap: 12, maxWidth: 640, width: "100%", alignSelf: "center" },
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 10, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  field: { gap: 8, paddingTop: 8, borderTopWidth: 1, borderTopColor: colors.border },
  label: { color: colors.text, fontWeight: "500" },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
});
