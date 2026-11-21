import React, { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { lastLink, loginLine, plainOutput, type LoginStream } from "../src/teammateLogins";
import { colors, HARNESS_NAMES } from "../src/theme";
import type { LoginEvent, TeammateLoginsView } from "../src/types";

interface Props {
  api: Pick<SuperBotApi, "teammateLogins" | "startTeammateLogin" | "teammateLoginInput" | "stopTeammateLogin" | "teammateLogout">;
  ownerId: string;
  ownerName: string;
  harness: string;
  /** False for read-only people: the server refuses their changes. */
  canWrite: boolean;
}

/** How much of a login's terminal to keep on screen. */
const SHOWN = 2000;

interface Running {
  id: string | null;
  output: string;
  stream: LoginStream;
}

/**
 * Your own login for a shared Bot's harness on its owner's computer (ADR 0062), or on this
 * server for the owner's Bots (ADR 0064). Your runs there use it; the owner's login is never
 * used for you, and nobody else can use yours.
 */
export function TeammateLoginPanel({ api, ownerId, ownerName, harness, canWrite }: Props) {
  const [view, setView] = useState<TeammateLoginsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [running, setRunning] = useState<Running | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const runningRef = useRef<Running | null>(null);
  const name = HARNESS_NAMES[harness] || harness;

  const load = useCallback(async () => {
    try {
      setView(await api.teammateLogins(ownerId));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api, ownerId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Leaving stops a login still running: the server ends it when nobody reads it.
  useEffect(() => () => runningRef.current?.stream.stop(), []);

  const update = (r: Running | null) => {
    runningRef.current = r;
    setRunning(r ? { ...r } : null);
  };

  const onEvent = (e: LoginEvent) => {
    const r = runningRef.current;
    if (!r) return;
    if (e.type === "started") r.id = e.loginId;
    else if (e.type === "output") r.output = (r.output + e.text).slice(-SHOWN);
    else if (e.type === "error") setError(e.message);
    else if (e.type === "exit") setNotice(e.loggedIn ? "Logged in." : "The login ended without logging in.");
    update(r);
  };

  const start = () => {
    setError(null);
    setNotice(null);
    setCode("");
    const r: Running = { id: null, output: "", stream: { stop: () => {}, done: Promise.resolve() } };
    runningRef.current = r;
    r.stream = api.startTeammateLogin(ownerId, harness, onEvent);
    update(r);
    r.stream.done
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => {
        if (runningRef.current === r) update(null);
        void load();
      });
  };

  const send = async () => {
    const id = running?.id;
    if (!id || !code) return;
    setBusy(true);
    try {
      await api.teammateLoginInput(ownerId, id, code);
      setCode("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const stop = () => {
    const r = runningRef.current;
    if (r?.id) void api.stopTeammateLogin(ownerId, r.id).catch(() => {});
    r?.stream.stop();
  };

  const logout = async () => {
    setBusy(true);
    setNotice(null);
    try {
      setView(await api.teammateLogout(ownerId, harness));
      setNotice("Logged out.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const login = view?.harnesses[harness];
  const shown = running ? plainOutput(running.output) : "";
  const link = running ? lastLink(running.output) : null;

  return (
    <View style={styles.box}>
      <Text style={styles.title}>Your {name} login</Text>
      <Text style={styles.dim}>{view ? loginLine(login, ownerName, view.on ?? "machine") : error ? "" : "Checking…"}</Text>
      {running ? (
        <>
          <Text style={styles.terminal} selectable>
            {shown || "Starting…"}
          </Text>
          {link ? (
            <Pressable role="button" aria-label="Open the login link" onPress={() => void Linking.openURL(link)}>
              <Text style={styles.link}>Open the login link</Text>
            </Pressable>
          ) : null}
          <View style={styles.row}>
            <TextInput
              style={styles.input}
              value={code}
              onChangeText={setCode}
              placeholder="Paste the code it asks for"
              placeholderTextColor={colors.textFaint}
              autoCapitalize="none"
              autoCorrect={false}
              secureTextEntry
              aria-label="Login code"
              onSubmitEditing={() => void send()}
            />
            <Pressable role="button" aria-label="Send code" disabled={busy || !code || !running.id} onPress={() => void send()}>
              <Text style={styles.link}>Send</Text>
            </Pressable>
          </View>
          <Pressable role="button" aria-label="Stop login" onPress={stop}>
            <Text style={styles.danger}>Stop</Text>
          </Pressable>
        </>
      ) : canWrite && view ? (
        login?.state === "logged_in" ? (
          <Pressable role="button" aria-label={`Log out of ${name}`} disabled={busy} onPress={() => void logout()}>
            <Text style={styles.danger}>Log out</Text>
          </Pressable>
        ) : (
          <Pressable role="button" aria-label={`Log in to ${name}`} disabled={busy} onPress={start}>
            <Text style={styles.link}>Log in with your own account</Text>
          </Pressable>
        )
      ) : null}
      {notice ? <Text style={styles.dim}>{notice}</Text> : null}
      {error ? <Text style={styles.error}>{error}</Text> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  box: { width: "100%", gap: 8, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.border },
  title: { color: colors.text },
  dim: { color: colors.textDim },
  row: { flexDirection: "row", alignItems: "center", gap: 10 },
  input: {
    flex: 1,
    color: colors.text,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 6,
  },
  terminal: {
    color: colors.text,
    fontFamily: "monospace",
    fontSize: 12,
    backgroundColor: colors.bgMain,
    padding: 8,
    borderRadius: 6,
  },
  link: { color: colors.blueDot },
  danger: { color: colors.danger },
  error: { color: colors.danger },
});
