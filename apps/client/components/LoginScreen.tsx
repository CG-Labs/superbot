import React, { useEffect, useState } from "react";
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
import { MfaRequired } from "../src/api";
import { defaultServerUrl } from "../src/auth";
import { fetchSsoProviders, ssoButtonText, ssoButtonTone, ssoSupported, type SsoProvider } from "../src/sso";
import { useSuperBot } from "../src/SuperBotContext";
import { colors, ThemeScope } from "../src/theme";
import { MfaSetupView, proofFrom, RecoveryCodes } from "./TwoFactor";

/** `inviteCode` fills in the code from an invite link; it is only spent on Connect. */
export function LoginScreen({ inviteCode = null }: { inviteCode?: string | null }) {
  const { login, loginSecondFactor, loginWithSso, error: bootError } = useSuperBot();
  const [baseUrl, setBaseUrl] = useState(() => defaultServerUrl());
  const [secret, setSecret] = useState(inviteCode ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [providers, setProviders] = useState<SsoProvider[]>([]);
  // The second step (ADR 0094): what the server asked for, the code typed, and the
  // recovery codes from setting it up, shown before the session starts.
  const [mfa, setMfa] = useState<MfaRequired | null>(null);
  const [factor, setFactor] = useState("");
  const [saved, setSaved] = useState<{ codes: string[]; finish: () => Promise<void> } | null>(null);

  // Ask the server which SSO providers it offers, once typing pauses.
  useEffect(() => {
    if (!ssoSupported()) return;
    let live = true;
    const t = setTimeout(() => {
      void fetchSsoProviders(baseUrl).then((list) => live && setProviders(list));
    }, 400);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [baseUrl]);

  const run = async (signIn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await signIn();
    } catch (err) {
      if (err instanceof MfaRequired) {
        setFactor("");
        // A wrong code comes back for the same challenge: keep the setup on screen.
        if (mfa?.challenge === err.challenge) setError(err.message);
        else setMfa(err);
        return;
      }
      if (mfa) {
        setMfa(null);
        setFactor("");
      }
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };
  const onSubmit = () => run(() => login(baseUrl, secret));
  const onVerify = () =>
    run(async () => {
      const proof = mfa?.mode === "enroll" ? { totp: factor.replace(/\s/g, "") } : proofFrom(factor);
      if (!mfa || !proof) return;
      const { recoveryCodes, finish } = await loginSecondFactor(baseUrl, mfa.challenge, proof);
      if (recoveryCodes) setSaved({ codes: recoveryCodes, finish });
      else await finish();
    });

  if (saved) {
    return (
      <View style={styles.wrap}>
        <View style={styles.card}>
          <Text style={styles.title}>SuperBot</Text>
          <Text style={styles.sub}>Two-factor authentication is on.</Text>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          <ThemeScope scheme="dark">
            <RecoveryCodes codes={saved.codes} doneLabel="I saved them. Continue" onDone={() => void run(saved.finish)} />
          </ThemeScope>
        </View>
      </View>
    );
  }

  if (mfa) {
    const enrolling = mfa.mode === "enroll";
    return (
      <KeyboardAvoidingView style={styles.wrap} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <View style={styles.card}>
          <Text style={styles.title}>SuperBot</Text>
          <Text style={styles.sub}>{enrolling ? "Set up two-factor authentication" : "Two-factor authentication"}</Text>
          <Text style={styles.hint}>{mfa.message}</Text>
          {enrolling && mfa.setup ? (
            <ThemeScope scheme="dark">
              <MfaSetupView setup={mfa.setup} />
            </ThemeScope>
          ) : null}
          <Text style={styles.label}>{enrolling ? "Code from your authenticator app" : "Code from your authenticator app, or a recovery code"}</Text>
          <TextInput
            style={styles.input}
            autoCapitalize="none"
            autoCorrect={false}
            autoComplete="one-time-code"
            inputMode={enrolling ? "numeric" : "text"}
            placeholder={enrolling ? "6-digit code" : "123456 or a recovery code"}
            placeholderTextColor={colors.textFaint}
            value={factor}
            onChangeText={setFactor}
            onSubmitEditing={onVerify}
            accessibilityLabel="Second factor"
          />
          {error ? <Text style={styles.error}>{error}</Text> : null}
          <Pressable style={[styles.btn, busy && styles.btnDisabled]} onPress={onVerify} disabled={busy || !factor.trim()}>
            {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>{enrolling ? "Turn on and connect" : "Verify"}</Text>}
          </Pressable>
          <Pressable onPress={() => (setMfa(null), setFactor(""), setError(null))} disabled={busy} accessibilityRole="button">
            <Text style={styles.back}>Start over</Text>
          </Pressable>
        </View>
      </KeyboardAvoidingView>
    );
  }

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
        {providers.length ? (
          <View style={styles.sso}>
            {providers.map((p) => {
              const apple = ssoButtonTone(p) === "apple";
              return (
                <Pressable
                  key={p.id}
                  style={[styles.ssoBtn, apple && styles.appleBtn, busy && styles.btnDisabled]}
                  onPress={() => run(() => loginWithSso(baseUrl, p.id))}
                  disabled={busy}
                >
                  <Text style={[styles.ssoText, apple && styles.appleText]}>{ssoButtonText(p)}</Text>
                </Pressable>
              );
            })}
            <Text style={styles.or}>or</Text>
          </View>
        ) : null}
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
        {inviteCode && secret === inviteCode ? (
          <Text style={styles.invited}>Your invite code is filled in. Check the server URL, then press Connect.</Text>
        ) : null}
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
  invited: { color: colors.accent, fontSize: 14 },
  error: { color: colors.danger, marginTop: 4 },
  btn: {
    marginTop: 16,
    backgroundColor: colors.blue,
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
  },
  btnDisabled: { opacity: 0.6 },
  sso: { marginTop: 16, gap: 10 },
  ssoBtn: {
    backgroundColor: colors.bgBubble,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
  },
  ssoText: { color: colors.text, fontWeight: "600", fontSize: 16 },
  appleBtn: { backgroundColor: "#fff", borderColor: "#fff" },
  appleText: { color: "#000" },
  or: { color: colors.textFaint, textAlign: "center", marginTop: 4 },
  btnText: { color: "#fff", fontWeight: "600", fontSize: 16 },
  back: { color: colors.blueDot, textAlign: "center", marginTop: 12 },
});