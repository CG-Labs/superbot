import React, { useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { ApiError, MfaRequired } from "../src/api";
import { defaultServerUrl } from "../src/auth";
import { fetchSsoProviders, ssoButtonText, ssoButtonTone, ssoSupported, type SsoProvider } from "../src/sso";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles, type, type Scheme } from "../src/theme";
import { Divider, Field, Notice, PrimaryButton, SignInFrame, TextButton } from "./SignInParts";
import { MfaSetupView, proofFrom, RecoveryCodes } from "./TwoFactor";

/**
 * Apple's button must be black or white with no other colour (its Human Interface
 * Guidelines), so it stays outside the design tokens: black on light, white on dark.
 */
export const APPLE_BUTTON: Record<Scheme, { bg: string; text: string }> = {
  light: { bg: "#000000", text: "#ffffff" },
  dark: { bg: "#ffffff", text: "#000000" },
};

/**
 * What to say when signing in fails. A request that never reached the server says so,
 * instead of the browser's or the phone's own wording; the server's messages pass through.
 */
export function signInErrorMessage(err: unknown, baseUrl: string): string {
  if (err instanceof ApiError) return err.status >= 500 && /^HTTP \d+$/.test(err.message) ? `The server at ${baseUrl} had a problem (${err.message}). Try again in a moment.` : err.message;
  if (err instanceof TypeError && /fetch|network|load failed/i.test(err.message)) {
    return `Can't reach a SuperBot server at ${baseUrl}. Check the server URL and your connection.`;
  }
  return err instanceof Error ? err.message : "Sign-in failed. Try again.";
}

/** `inviteCode` fills in the code from an invite link; it is only spent on Connect. */
export function LoginScreen({ inviteCode = null }: { inviteCode?: string | null }) {
  const { login, loginSecondFactor, loginWithSso, error: bootError } = useSuperBot();
  const styles = useStyles();
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
      setError(signInErrorMessage(err, baseUrl));
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
      <SignInFrame title="Two-factor authentication is on" subtitle="One last step before you start.">
        {error ? <Notice tone="danger">{error}</Notice> : null}
        <RecoveryCodes codes={saved.codes} doneLabel="I saved them. Continue" onDone={() => void run(saved.finish)} />
      </SignInFrame>
    );
  }

  if (mfa) {
    const enrolling = mfa.mode === "enroll";
    return (
      <SignInFrame title={enrolling ? "Set up two-factor authentication" : "Two-factor authentication"} subtitle={mfa.message}>
        {enrolling && mfa.setup ? <MfaSetupView setup={mfa.setup} /> : null}
        <Field
          label={enrolling ? "Code from your authenticator app" : "Code from your authenticator app, or a recovery code"}
          accessibilityLabel="Second factor"
          autoCapitalize="none"
          autoCorrect={false}
          autoComplete="one-time-code"
          inputMode={enrolling ? "numeric" : "text"}
          placeholder={enrolling ? "6-digit code" : "123456 or a recovery code"}
          value={factor}
          onChangeText={setFactor}
          onSubmitEditing={onVerify}
        />
        {error ? <Notice tone="danger">{error}</Notice> : null}
        <PrimaryButton label={enrolling ? "Turn on and connect" : "Verify"} onPress={onVerify} busy={busy} disabled={!factor.trim()} />
        <TextButton label="Start over" onPress={() => (setMfa(null), setFactor(""), setError(null))} disabled={busy} />
      </SignInFrame>
    );
  }

  const shownError = error || bootError;
  return (
    <SignInFrame title="Welcome to SuperBot" subtitle="Connect to your self-hosted server">
      <Field
        label="Server URL"
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="url"
        placeholder="https://your-server:3000"
        value={baseUrl}
        onChangeText={setBaseUrl}
      />
      {providers.length ? (
        <>
          <View style={styles.sso}>
            {providers.map((p) => (
              <SsoButton key={p.id} provider={p} disabled={busy} onPress={() => run(() => loginWithSso(baseUrl, p.id))} />
            ))}
          </View>
          <Divider label="or" />
        </>
      ) : null}
      <Field
        label="Sign-in code or password"
        secureTextEntry
        autoCapitalize="none"
        autoCorrect={false}
        placeholder="sbc_… or AUTH_PASSWORD"
        value={secret}
        onChangeText={setSecret}
      />
      {inviteCode && secret === inviteCode ? <Notice tone="info">Your invite code is filled in. Check the server URL, then press Connect.</Notice> : null}
      {shownError ? <Notice tone="danger">{shownError}</Notice> : null}
      <PrimaryButton label="Connect" onPress={onSubmit} busy={busy} />
      <Text style={styles.hint}>
        Ask an admin for a one-time sign-in code. The owner can use the server password. The app keeps a session token, not the password.
      </Text>
    </SignInFrame>
  );
}

/** One provider's button: a pill on the card, or Apple's own black or white. */
function SsoButton({ provider, disabled, onPress }: { provider: SsoProvider; disabled: boolean; onPress: () => void }) {
  const styles = useStyles();
  const apple = ssoButtonTone(provider) === "apple";
  const label = ssoButtonText(provider);
  return (
    <Pressable
      style={({ pressed }) => [styles.ssoBtn, apple && styles.appleBtn, disabled && styles.disabled, pressed && styles.pressed]}
      onPress={onPress}
      disabled={disabled}
      accessibilityRole="button"
      accessibilityLabel={label}
    >
      <Text style={[styles.ssoText, apple && styles.appleText]}>{label}</Text>
    </Pressable>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    sso: { gap: t.space.sm + 2 },
    ssoBtn: {
      minHeight: 48,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.borderStrong,
      backgroundColor: t.c.raised,
      alignItems: "center",
      justifyContent: "center",
      paddingHorizontal: t.space.xl,
    },
    ssoText: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.semibold },
    appleBtn: { backgroundColor: APPLE_BUTTON[t.scheme].bg, borderColor: APPLE_BUTTON[t.scheme].bg },
    appleText: { color: APPLE_BUTTON[t.scheme].text },
    disabled: { opacity: 0.55 },
    pressed: { opacity: 0.75 },
    hint: { color: t.c.textFaint, ...type(t, "sm"), textAlign: "center" },
  }),
);
