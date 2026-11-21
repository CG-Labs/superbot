import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Linking, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { SvgXml } from "react-native-svg";
import type { SuperBotApi } from "../src/api";
import { COPY_LABEL, copyText } from "../src/clipboard";
import { confirmAsync } from "../src/dialogs";
import { colors } from "../src/theme";
import type { MfaPolicy, MfaProof, MfaSetup, MfaStatus } from "../src/types";
import { Chips } from "./Chips";

/** A typed code: six digits for the app, anything else is a recovery code. */
export function proofFrom(input: string): MfaProof | null {
  const v = input.trim();
  if (!v) return null;
  const digits = v.replace(/\s/g, "");
  return /^\d{6}$/.test(digits) ? { totp: digits } : { recoveryCode: v };
}

/** The key to add to an authenticator app: its QR code, the key to type, and a link. */
export function MfaSetupView({ setup }: { setup: MfaSetup }) {
  return (
    <View style={styles.setup} testID="mfa-setup">
      {setup.qrSvg ? (
        <View style={styles.qr} accessibilityLabel="QR code to add SuperBot to an authenticator app">
          <SvgXml xml={setup.qrSvg} width={176} height={176} />
        </View>
      ) : null}
      <Text style={styles.dim}>Or enter this key in the app:</Text>
      <Text style={styles.key} selectable testID="mfa-key">
        {setup.secret.replace(/(.{4})/g, "$1 ").trim()}
      </Text>
      <Pressable onPress={() => void Linking.openURL(setup.otpauthUrl).catch(() => {})} accessibilityRole="link">
        <Text style={styles.link}>Open in an authenticator app on this device</Text>
      </Pressable>
    </View>
  );
}

/** Recovery codes, shown this once: the server keeps only their hashes. */
export function RecoveryCodes({ codes, onDone, doneLabel = "I saved them" }: { codes: string[]; onDone: () => void; doneLabel?: string }) {
  const [copied, setCopied] = useState<boolean | null>(null);
  return (
    <View style={styles.codesWrap} testID="recovery-codes">
      <Text style={styles.warn}>Save these recovery codes somewhere safe. Each works once if you lose your authenticator app. They can&apos;t be shown again.</Text>
      <View style={styles.codes}>
        {codes.map((c) => (
          <Text key={c} style={styles.code} selectable>
            {c}
          </Text>
        ))}
      </View>
      <View style={styles.row}>
        <Pressable style={styles.btn} onPress={() => void copyText(codes.join("\n")).then(setCopied)}>
          <Text style={styles.btnText}>{copied ? "Copied" : copied === false ? "Select and copy them" : `${COPY_LABEL} codes`}</Text>
        </Pressable>
        <Pressable style={[styles.btn, styles.primary]} onPress={onDone}>
          <Text style={[styles.btnText, styles.primaryText]}>{doneLabel}</Text>
        </Pressable>
      </View>
    </View>
  );
}

export type MfaApi = Pick<SuperBotApi, "mfaStatus" | "mfaEnroll" | "mfaConfirm" | "mfaNewRecoveryCodes" | "mfaDisable" | "setMfaPolicy">;

const POLICY_LABELS: { value: MfaPolicy; label: string }[] = [
  { value: "off", label: "No one" },
  { value: "admins", label: "Admins" },
  { value: "all", label: "Everyone" },
];

/**
 * Your own two-factor authentication (ADR 0094), and for admins who must have it. It
 * protects sign-in codes and the password; single sign-on relies on your IdP's MFA.
 */
export function TwoFactorCard({ api, admin = false }: { api: MfaApi; admin?: boolean }) {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [input, setInput] = useState("");
  const [asking, setAsking] = useState<"codes" | "off" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await api.mfaStatus());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);
  useEffect(() => {
    void load();
  }, [load]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const start = () => run(async () => setSetup(await api.mfaEnroll()));
  const cancel = () =>
    run(async () => {
      setSetup(null);
      setInput("");
      setStatus(await api.mfaDisable());
    });
  const confirm = () =>
    run(async () => {
      const r = await api.mfaConfirm(input.replace(/\s/g, ""));
      setSetup(null);
      setInput("");
      setCodes(r.recoveryCodes);
      setStatus(r);
    });
  const prove = () =>
    run(async () => {
      const proof = proofFrom(input);
      if (!proof) return;
      if (asking === "codes") {
        const r = await api.mfaNewRecoveryCodes(proof);
        setCodes(r.recoveryCodes);
        setStatus(r);
      } else {
        setStatus(await api.mfaDisable(proof));
      }
      setAsking(null);
      setInput("");
    });
  const setPolicy = async (p: MfaPolicy) => {
    if (!status || p === status.policy) return;
    if (p !== "off" && !(await confirmAsync("Require two-factor authentication?", "Sessions already open stay open. Each person it covers sets it up at their next sign-in with a code or the password. The owner's password then works only at sign-in, not over HTTP Basic.", "Require"))) return;
    void run(async () => setStatus(await api.setMfaPolicy(p)));
  };

  return (
    <View style={styles.card} accessibilityLabel="Two-factor authentication">
      <Text style={styles.cardTitle}>Two-factor authentication</Text>
      <Text style={styles.dim}>
        Ask for a code from an authenticator app when you sign in with a sign-in code or the password. Single sign-on uses your identity provider&apos;s MFA instead.
      </Text>
      {error ? (
        <Text style={styles.error} accessibilityRole="alert">
          {error}
        </Text>
      ) : null}
      {!status ? (
        <ActivityIndicator color={colors.textDim} />
      ) : codes ? (
        <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />
      ) : setup ? (
        <>
          <MfaSetupView setup={setup} />
          <TextInput
            style={styles.input}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="6-digit code"
            placeholderTextColor={colors.textFaint}
            value={input}
            onChangeText={setInput}
            accessibilityLabel="Code from your authenticator app"
          />
          <View style={styles.row}>
            <Pressable style={[styles.btn, styles.primary, busy && styles.disabled]} disabled={busy || !input.trim()} onPress={() => void confirm()}>
              <Text style={[styles.btnText, styles.primaryText]}>Turn on</Text>
            </Pressable>
            <Pressable style={styles.btn} disabled={busy} onPress={() => void cancel()}>
              <Text style={styles.btnText}>Cancel</Text>
            </Pressable>
          </View>
        </>
      ) : asking ? (
        <>
          <Text style={styles.text}>{asking === "codes" ? "To make new recovery codes" : "To turn it off"}, enter the code from your authenticator app, or a recovery code.</Text>
          <TextInput
            style={styles.input}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="Code or recovery code"
            placeholderTextColor={colors.textFaint}
            value={input}
            onChangeText={setInput}
            accessibilityLabel="Code or recovery code"
          />
          <View style={styles.row}>
            <Pressable style={[styles.btn, styles.primary, busy && styles.disabled]} disabled={busy || !input.trim()} onPress={() => void prove()}>
              <Text style={[styles.btnText, styles.primaryText]}>{asking === "codes" ? "Make new codes" : "Turn off"}</Text>
            </Pressable>
            <Pressable style={styles.btn} disabled={busy} onPress={() => (setAsking(null), setInput(""))}>
              <Text style={styles.btnText}>Cancel</Text>
            </Pressable>
          </View>
        </>
      ) : (
        <>
          <Text style={styles.text} testID="mfa-state">
            {status.enabled
              ? `On, with ${status.recoveryCodesLeft} recovery code${status.recoveryCodesLeft === 1 ? "" : "s"} left.`
              : status.required
                ? "Off. This server requires it for you, so your next sign-in sets it up."
                : "Off."}
          </Text>
          <View style={styles.row}>
            {status.enabled ? (
              <>
                <Pressable style={styles.btn} disabled={busy} onPress={() => setAsking("codes")}>
                  <Text style={styles.btnText}>New recovery codes</Text>
                </Pressable>
                {status.required ? null : (
                  <Pressable style={styles.btn} disabled={busy} onPress={() => setAsking("off")}>
                    <Text style={[styles.btnText, styles.dangerText]}>Turn off</Text>
                  </Pressable>
                )}
              </>
            ) : (
              <Pressable style={[styles.btn, styles.primary, busy && styles.disabled]} disabled={busy} onPress={() => void start()}>
                <Text style={[styles.btnText, styles.primaryText]}>Turn on</Text>
              </Pressable>
            )}
          </View>
          {admin ? (
            <View style={styles.field} accessibilityLabel="Who must use two-factor authentication">
              <Text style={styles.label}>Required for</Text>
              <Chips options={POLICY_LABELS} value={status.policy} onChange={(p) => void setPolicy(p)} disabled={busy || status.policyPinned} />
              <Text style={styles.faint}>
                {status.policyPinned ? "Set by AUTH_MFA on the server." : "Admins includes the owner account. Require MFA at your identity provider too, for single sign-on."}
              </Text>
            </View>
          ) : null}
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 10, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  field: { gap: 8, paddingTop: 8, borderTopWidth: 1, borderTopColor: colors.border },
  label: { color: colors.text, fontWeight: "500" },
  text: { color: colors.text },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 13 },
  warn: { color: colors.warning },
  error: { color: colors.danger },
  link: { color: colors.blueDot },
  setup: { gap: 8, alignItems: "flex-start" },
  qr: { backgroundColor: "#fff", padding: 8, borderRadius: 12 },
  key: { color: colors.text, fontFamily: "monospace", fontSize: 15 },
  codesWrap: { gap: 10 },
  codes: { flexDirection: "row", flexWrap: "wrap", gap: 8, padding: 12, borderRadius: 12, borderWidth: 1, borderColor: colors.border },
  code: { color: colors.text, fontFamily: "monospace", fontSize: 15, width: "45%" },
  row: { flexDirection: "row", flexWrap: "wrap", gap: 8, alignItems: "center" },
  input: { backgroundColor: colors.bgBubble, borderColor: colors.border, borderWidth: 1, borderRadius: 12, paddingHorizontal: 14, paddingVertical: 12, color: colors.text, fontSize: 16 },
  btn: { borderRadius: 10, borderWidth: 1, borderColor: colors.border, paddingHorizontal: 14, paddingVertical: 8 },
  btnText: { color: colors.text },
  primary: { backgroundColor: colors.blue, borderColor: colors.blue },
  primaryText: { color: "#fff", fontWeight: "600" },
  dangerText: { color: colors.danger },
  disabled: { opacity: 0.5 },
});
