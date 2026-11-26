import React, { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { errorText, friendlyError } from "../src/errors";
import { lastLink, loginLine, plainOutput, type LoginStream } from "../src/teammateLogins";
import { hairline, HARNESS_NAMES, themedStyles, type } from "../src/theme";
import type { LoginEvent, TeammateLoginsView } from "../src/types";
import { InlineError } from "./ErrorState";
import { ListSkeleton } from "./Skeleton";
import { kit, usePlaceholder } from "./ui";

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
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const [view, setView] = useState<TeammateLoginsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Why your login couldn't be checked, apart from a failed action, so it can offer a retry. */
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [running, setRunning] = useState<Running | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const runningRef = useRef<Running | null>(null);
  const name = HARNESS_NAMES[harness] || harness;

  const load = useCallback(async () => {
    try {
      setView(await api.teammateLogins(ownerId));
      setLoadError(null);
    } catch (e) {
      setLoadError(errorText(e, `Couldn't check your ${name} login`));
    }
  }, [api, ownerId, name]);

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
      .catch((e: unknown) => setError(friendlyError(e)))
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
      setError(friendlyError(e));
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
      setError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  const login = view?.harnesses[harness];
  const shown = running ? plainOutput(running.output) : "";
  const link = running ? lastLink(running.output) : null;

  return (
    <View style={styles.box}>
      <Text style={styles.title} role="heading">
        Your {name} login
      </Text>
      {view ? (
        <Text style={styles.dim}>{loginLine(login, ownerName, view.on ?? "machine")}</Text>
      ) : loadError ? null : (
        <ListSkeleton label={`Loading your ${name} login`} rows={1} />
      )}
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
              placeholderTextColor={placeholder}
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
      {loadError ? <InlineError message={loadError} onRetry={load} /> : null}
      {error ? <InlineError message={error} /> : null}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    box: { width: "100%", gap: t.space.sm, paddingVertical: t.space.sm, borderBottomWidth: hairline, borderBottomColor: t.c.border },
    title: { ...k.text, fontWeight: t.font.weight.medium },
    dim: { color: t.c.textMuted, ...type(t, "md") },
    row: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    input: { ...k.input, flex: 1, paddingVertical: t.space.xs },
    terminal: {
      color: t.c.text,
      fontFamily: t.font.mono,
      ...type(t, "xs"),
      backgroundColor: t.c.codeBg,
      padding: t.space.sm,
      borderRadius: t.radius.sm,
    },
    link: k.link,
    danger: { color: t.c.danger, ...type(t, "md") },
  });
});
