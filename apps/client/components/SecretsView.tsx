import React, { useCallback, useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { managedIn, normalizeSecretName, savedLine, secretNameProblem, secretValueProblem } from "../src/secrets";
import { themedStyles, type } from "../src/theme";
import type { PersonalSecret } from "../src/types";
import { kit, PageHeader, Spinner, usePlaceholder } from "./ui";

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
  const styles = useStyles();
  const placeholder = usePlaceholder();
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
  const existing = list?.find((s) => s.name === target);
  const exists = !!existing;
  /** An admin keeps `target` for you elsewhere, so a value saved here wouldn't be used. */
  const existingIn = existing ? managedIn(existing) : null;
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
    // The value leaves the screen as it is sent, whatever the server answers; a refused
    // one is pasted again. The form is locked until then, so no newer draft is lost.
    const sent = value;
    setValue("");
    setBusy("save");
    setError(null);
    setNotice(null);
    try {
      const saved = await api.setMySecret(target, sent);
      resetForm();
      setNotice(
        existingIn
          ? `Saved ${saved.name} here, but your Bots keep the value an admin set for you in ${existingIn}.`
          : exists
            ? `Replaced ${saved.name}. Your Bots get the new value on their next run.`
            : `Saved ${saved.name}. Your Bots get it on their next run.`,
      );
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (s: PersonalSecret) => {
    const store = managedIn(s);
    const after = store
      ? `Your Bots keep the value an admin set for you in ${store}.`
      : s.overrides
        ? "Your Bots go back to the server's value."
        : "Your Bots stop getting it.";
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

  const header = <PageHeader title="Your secrets" onBack={onBack} />;

  if (list === undefined && !error) {
    return (
      <View style={styles.root}>
        {header}
        <Spinner style={styles.loading} />
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
          <View style={styles.list}>
            {list.map((s, i) => (
              <View key={s.name} style={[styles.item, i === 0 && styles.itemFirst]}>
                <View style={styles.grow}>
                  <Text style={styles.name} selectable>
                    {s.name}
                  </Text>
                  <Text style={styles.dim}>{savedLine(s)}</Text>
                  {s.overrides ? <Text style={styles.dim}>The server has one with this name too; yours wins for your Bots.</Text> : null}
                </View>
                {canWrite && (!managedIn(s) || s.saved) ? (
                  <View style={styles.row}>
                    {managedIn(s) ? null : (
                      <Pressable
                        style={[styles.btn, styles.small, !!busy && styles.busy]}
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
                    )}
                    <Pressable
                      style={[styles.btn, styles.small, styles.dangerBtn, !!busy && styles.busy]}
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
            ))}
          </View>
        ) : list ? (
          <View style={styles.list}>
            <Text style={styles.empty}>No secrets yet.</Text>
          </View>
        ) : null}
        {canWrite ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>{replacing ? `New value for ${replacing}` : "Add a secret"}</Text>
            {replacing ? null : (
              <TextInput
                style={[styles.input, styles.mono]}
                placeholder="Name, like OPENAI_API_KEY"
                placeholderTextColor={placeholder}
                value={name}
                onChangeText={setName}
                onBlur={() => setName((n) => normalizeSecretName(n))}
                autoCapitalize="characters"
                editable={!busy}
                autoCorrect={false}
                accessibilityLabel="Secret name"
              />
            )}
            <TextInput
              style={[styles.input, styles.mono]}
              placeholder="Value"
              placeholderTextColor={placeholder}
              value={value}
              onChangeText={setValue}
              secureTextEntry
              editable={!busy}
              autoCapitalize="none"
              autoCorrect={false}
              autoComplete="off"
              importantForAutofill="no"
              accessibilityLabel="Secret value"
            />
            {problem ? <Text style={styles.warn}>{problem}</Text> : null}
            {!replacing && existingIn ? (
              <Text style={styles.warn}>
                An admin set {target} for you in {existingIn}. That value wins, so one saved here isn&apos;t used.
              </Text>
            ) : !replacing && exists ? (
              <Text style={styles.warn}>You already have {target}; saving replaces its value.</Text>
            ) : null}
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
                <Pressable style={[styles.btn, !!busy && styles.busy]} disabled={!!busy} onPress={resetForm} accessibilityRole="button">
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    loading: { marginTop: t.space.xxl },
    body: k.body,
    good: k.good,
    error: k.error,
    warn: k.warn,
    dim: k.dim,
    card: k.card,
    cardTitle: k.cardTitle,
    list: { ...k.card, gap: 0, paddingVertical: t.space.xs },
    item: { ...k.row, flexWrap: "wrap" },
    itemFirst: k.rowFirst,
    grow: { flex: 1, minWidth: 160, gap: t.space.xxs },
    empty: k.empty,
    name: { ...k.mono, ...type(t, "md"), fontWeight: t.font.weight.medium },
    mono: { fontFamily: t.font.mono },
    input: k.input,
    row: k.actions,
    btn: k.btn,
    small: k.btnSmall,
    btnText: k.btnText,
    dangerBtn: k.danger,
    dangerText: { ...k.btnText, ...k.dangerText },
    primaryBtn: { ...k.btn, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    busy: k.disabled,
  });
});
