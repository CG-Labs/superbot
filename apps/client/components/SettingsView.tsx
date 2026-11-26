import React, { useState } from "react";
import { ScrollView, StyleSheet, Text, View } from "react-native";
import { availabilityProblem, LOCK_AFTER_OPTIONS, lockAfterLabel } from "../src/appLock";
import { friendlyError } from "../src/errors";
import { themedStyles } from "../src/theme";
import { useAppLock } from "./AppLock";
import { Chips } from "./Chips";
import { InlineError } from "./ErrorState";
import { PushCard, type PushApi } from "./PushCard";
import { ResidencyCard, type ResidencyApi } from "./ResidencyCard";
import { RoleRequestsCard, type RoleRequestsApi } from "./RoleRequestsCard";
import { ListSkeleton } from "./Skeleton";
import { TwoFactorCard, type MfaApi } from "./TwoFactor";
import { kit, PageHeader } from "./ui";

interface Props {
  onBack: () => void;
  /** The signed-in server, for this phone's push notifications (ADR 0080), your second factor (ADR 0094), your data's residency pin (ADR 0168) and requests for roles (ADR 0209). */
  api?: PushApi & MfaApi & ResidencyApi & RoleRequestsApi;
  /** Admins also set who must use two-factor authentication. */
  admin?: boolean;
}

/** This device's own settings: App lock is kept on the device, push on the server for this session. */
export function SettingsView({ onBack, api, admin = false }: Props) {
  const styles = useStyles();
  return (
    <View style={styles.root}>
      <PageHeader title="Settings" onBack={onBack} />
      <ScrollView contentContainerStyle={styles.body}>
        <Text style={styles.section} role="heading">
          This device
        </Text>
        <AppLockCard />
        {api ? <PushCard api={api} /> : null}
        {api ? (
          <>
            <Text style={styles.section} role="heading">
              Your account
            </Text>
            <TwoFactorCard api={api} admin={admin} />
            <ResidencyCard api={api} />
            {!admin ? <RoleRequestsCard api={api} /> : null}
          </>
        ) : null}
      </ScrollView>
    </View>
  );
}

/** App lock (ADR 0078): off by default, and unavailable where there are no biometrics. */
export function AppLockCard() {
  const styles = useStyles();
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
      setError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  if (!availability) {
    return (
      <View style={styles.card} accessibilityLabel="App lock">
        <Text style={styles.cardTitle} role="heading">
          App lock
        </Text>
        <ListSkeleton label="Loading App lock" rows={2} />
      </View>
    );
  }

  const problem = availabilityProblem(availability);
  if (availability.kind === "unsupported") {
    return (
      <View style={styles.card} accessibilityLabel="App lock">
        <Text style={styles.cardTitle} role="heading">
          App lock
        </Text>
        <Text style={styles.dim}>{problem}</Text>
      </View>
    );
  }

  const label = availability.kind === "available" || availability.kind === "not-enrolled" ? availability.label : "biometrics";
  return (
    <View style={styles.card} accessibilityLabel="App lock">
      <Text style={styles.cardTitle} role="heading">
        App lock
      </Text>
      <Text style={styles.dim}>
        Ask for {label} or your device passcode when SuperBot opens, and hide your chats in the app switcher. This is kept on this device only; signing out turns it off.
      </Text>
      {notice ? (
        <Text style={styles.good} accessibilityRole="alert">
          {notice}
        </Text>
      ) : null}
      {error ? <InlineError message={error} /> : null}
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    body: k.body,
    section: k.section,
    card: k.card,
    cardTitle: k.cardTitle,
    field: k.field,
    label: k.label,
    good: k.good,
    warn: k.warn,
    dim: k.dim,
  });
});
