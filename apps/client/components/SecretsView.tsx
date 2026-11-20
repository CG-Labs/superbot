import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { normalizeSecretName, savedLine, secretNameProblem, secretValueProblem } from "../src/secrets";
import { colors } from "../src/theme";
import type { PersonalSecret } from "../src/types";

interface Props {
  api: Pick<SuperBotApi, "mySecrets" | "setMySecret" | "deleteMySecret">;
  onBack: () => void;
  /** False for read-only people: the server refuses their changes. */
  canWrite: boolean;
  /** Asks before deleting; `confirmAsync` unless a test swaps it. */
  confirm?: (title: string, message: string) => Promise<boolean>;
}

/**
 * Your own secrets (ADR 0044): API keys your Bots get as environment variables. Names and
 * dates only; a value is sent once and never shown again, so it isn't kept here either.
 */
export function SecretsView({ api, onBack, canWrite, confirm = confirmAsync }: Props) {
  const [list, setList] = useState<PersonalSecret[] | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  /** The secret whose value is being replaced; its name is fixed. */
  const [replacing, setReplacing] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setList(await api.mySecrets());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const target = replacing ?? normalizeSecretName(name);
  const exists = !!list?.some((s) => s.name === target);
  const problem = (name || replacing ? secretNameProblem(target) : null) ?? (value ? secretValueProblem(value) : null);

  const resetForm = () => {
    setName("");
    setValue("");
    setReplacing(null);
  };

  const save = async () => {
    const bad = secretNameProblem(target) ?? secretValueProblem(value);
    if (bad) {
      setError(bad);
      return;
    }
    setBusy("save");
    setError(null);
    setNotice(null);
    try {
      const saved = await api.setMySecret(target, value);
      resetForm();
      setNotice(exists ? `Replaced ${saved.name}. Your Bots get the new value on their next run.` : `Saved ${saved.name}. Your Bots get it on their next run.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (s: PersonalSecret) => {
    const after = s.overrides ? "Your Bots go back to the server's value." : "Your Bots stop getting it.";
    if (!(await confirm(`Delete ${s.name}?`, `${after} This can't be undone.`))) return;
    setBusy(s.name);
    setError(null);
    setNotice(null);
    try {
      await api.deleteMySecret(s.name);
      if (replacing === s.name) resetForm();
      setNotice(`Deleted ${s.name}.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const header = (
    <View style={styles.header}>
      <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
        <Text style={styles.back}>‹ Bots</Text>
      </Pressable>
      <Text style={styles.title}>Your secrets</Text>
    </View>
  );

  if (list === undefined && !error) {
    return (
      <View style={styles.root}>
        {header}
        <ActivityIndicator style={styles.loading} color={colors.textDim} />
      </View>
    );
  }

  return (
    <View style={styles.root}>
      {header}
      <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
        <Text style={styles.dim}>
          API keys and tokens for your own Bots. Each one reaches only Bots you own, as an environment variable, also when someone you share a Bot with uses
          it. Nobody else's Bots get them, and nobody can read a value back, you included.
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
        {list?.length ? (
          list.map((s) => (
            <View key={s.name} style={styles.card}>
              <Text style={styles.name} selectable>
                {s.name}
              </Text>
              <Text style={styles.dim}>{savedLine(s)}</Text>
              {s.overrides ? <Text style={styles.dim}>The server has one with this name too; yours wins for your Bots.</Text> : null}
              {canWrite ? (
                <View style={styles.row}>
                  <Pressable
                    style={[styles.btn, !!busy && styles.busy]}
                    disabled={!!busy}
                    onPress={() => {
                      setReplacing(s.name);
                      setName("");
                      setValue("");
                      setNotice(null);
                    }}
                    accessibilityRole="button"
                    accessibilityLabel={`Replace ${s.name}`}
                  >
                    <Text style={styles.btnText}>Replace</Text>
                  </Pressable>
                  <Pressable
                    style={[styles.btn, !!busy && styles.busy]}
                    disabled={!!busy}
                    onPress={() => void remove(s)}
                    accessibilityRole="button"
                    accessibilityLabel={`Delete ${s.name}`}
                  >
                    <Text style={styles.dangerText}>{busy === s.name ? "Deleting…" : "Delete"}</Text>
                  </Pressable>
                </View>
              ) : null}
            </View>
          ))
        ) : list ? (
          <Text style={styles.dim}>No secrets yet.</Text>
        ) : null}
        {canWrite ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>{replacing ? `New value for ${replacing}` : "Add a secret"}</Text>
            {replacing ? null : (
              <TextInput
                style={[styles.input, styles.mono]}
                placeholder="Name, like OPENAI_API_KEY"
                placeholderTextColor={colors.textFaint}
                value={name}
                onChangeText={setName}
                onBlur={() => setName((n) => normalizeSecretName(n))}
                autoCapitalize="characters"
                autoCorrect={false}
                accessibilityLabel="Secret name"
              />
            )}
            <TextInput
              style={[styles.input, styles.mono]}
              placeholder="Value"
              placeholderTextColor={colors.textFaint}
              value={value}
              onChangeText={setValue}
              secureTextEntry
              autoCapitalize="none"
              autoCorrect={false}
              autoComplete="off"
              importantForAutofill="no"
              accessibilityLabel="Secret value"
            />
            {problem ? <Text style={styles.warn}>{problem}</Text> : null}
            {!replacing && exists ? <Text style={styles.warn}>You already have {target}; saving replaces its value.</Text> : null}
            <View style={styles.row}>
              <Pressable
                style={[styles.primaryBtn, (!!busy || !!problem || !value || !target) && styles.busy]}
                disabled={!!busy || !!problem || !value || !target}
                onPress={() => void save()}
                accessibilityRole="button"
                accessibilityLabel={exists ? `Save new value for ${target}` : "Save secret"}
              >
                <Text style={styles.primaryText}>{busy === "save" ? "Saving…" : exists ? "Replace" : "Save"}</Text>
              </Pressable>
              {replacing ? (
                <Pressable style={styles.btn} onPress={resetForm} accessibilityRole="button">
                  <Text style={styles.btnText}>Cancel</Text>
                </Pressable>
              ) : null}
            </View>
          </View>
        ) : (
          <Text style={styles.dim}>Read-only accounts can't add or change secrets. Ask an admin.</Text>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  header: { flexDirection: "row", alignItems: "center", gap: 16, padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border },
  back: { color: colors.blueDot, fontSize: 16 },
  title: { color: colors.text, fontSize: 20, fontWeight: "600", flex: 1 },
  loading: { marginTop: 32 },
  body: { padding: 16, gap: 12, maxWidth: 640, width: "100%", alignSelf: "center" },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 6, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  name: { color: colors.text, fontSize: 15, fontFamily: "monospace" },
  mono: { fontFamily: "monospace" },
  input: {
    backgroundColor: colors.bgHover,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
  },
  row: { flexDirection: "row", gap: 8, marginTop: 8 },
  btn: { borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingVertical: 8, paddingHorizontal: 16 },
  btnText: { color: colors.text, fontSize: 15 },
  dangerText: { color: colors.danger, fontSize: 15 },
  primaryBtn: { backgroundColor: "#f2f2f2", borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16 },
  primaryText: { color: "#111", fontSize: 15 },
  busy: { opacity: 0.6 },
});
