import React, { useState } from "react";
import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { cleanPrompts, MAX_PROMPTS, validatePrompts } from "../src/prompts";
import { colors } from "../src/theme";

interface Props {
  /** What the Bot shows now: its own prompts or the defaults. */
  prompts: string[];
  /** True when the Bot has its own; false when it shows the defaults. */
  custom: boolean;
  /** Saves the list, or null to go back to the defaults. */
  onSave: (prompts: string[] | null) => Promise<void>;
  onCancel: () => void;
}

/** Edits a Bot's suggested prompts (ADR 0054), for those who manage it. */
export function PromptsEditor({ prompts, custom, onSave, onCancel }: Props) {
  const [list, setList] = useState<string[]>(prompts.length ? prompts : [""]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (value: string[] | null) => {
    setBusy(true);
    setError(null);
    try {
      await onSave(value);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  };

  const save = () => {
    const invalid = validatePrompts(list);
    if (invalid) {
      setError(invalid);
      return;
    }
    void run(cleanPrompts(list));
  };

  return (
    <View style={styles.form}>
      <Text style={styles.heading} role="heading">
        Suggested prompts
      </Text>
      <Text style={styles.hint}>
        Everyone who can run this Bot sees these. End one with … to let them finish it before sending.
      </Text>
      {list.map((p, i) => (
        <View key={i} style={styles.row}>
          <TextInput
            aria-label={`Prompt ${i + 1}`}
            style={styles.input}
            placeholder={i === 0 ? "Check the build and tell me what broke" : "Another prompt"}
            placeholderTextColor={colors.textFaint}
            value={p}
            editable={!busy}
            onChangeText={(t) => setList((l) => l.map((x, k) => (k === i ? t : x)))}
          />
          <Pressable
            role="button"
            aria-label={`Remove prompt ${i + 1}`}
            hitSlop={8}
            style={styles.remove}
            disabled={busy}
            onPress={() => setList((l) => l.filter((_, k) => k !== i))}
          >
            <Text style={styles.removeText}>✕</Text>
          </Pressable>
        </View>
      ))}
      {list.length < MAX_PROMPTS ? (
        <Pressable role="button" aria-label="Add prompt" disabled={busy} onPress={() => setList((l) => [...l, ""])}>
          <Text style={styles.link}>+ Add prompt</Text>
        </Pressable>
      ) : null}
      {error ? (
        <Text style={styles.error} role="alert">
          {error}
        </Text>
      ) : null}
      <View style={styles.actions}>
        {custom ? (
          <Pressable role="button" aria-label="Use the default prompts" disabled={busy} onPress={() => void run(null)}>
            <Text style={styles.reset}>Use defaults</Text>
          </Pressable>
        ) : null}
        <View style={{ flex: 1 }} />
        <Pressable role="button" aria-label="Cancel" disabled={busy} onPress={onCancel}>
          <Text style={styles.cancel}>Cancel</Text>
        </Pressable>
        <Pressable role="button" aria-label="Save prompts" style={styles.save} disabled={busy} onPress={save}>
          <Text style={styles.saveText}>{busy ? "Saving…" : "Save"}</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  form: { width: "100%", gap: 8 },
  heading: { color: colors.text, fontSize: 18, fontWeight: "700" },
  hint: { color: colors.textFaint, fontSize: 12 },
  row: { flexDirection: "row", alignItems: "center", gap: 8 },
  input: {
    flex: 1,
    backgroundColor: colors.bgBubble,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 12,
    color: colors.text,
  },
  remove: { padding: 8 },
  removeText: { color: colors.textDim, fontSize: 16 },
  link: { color: colors.blueDot, paddingVertical: 6 },
  error: { color: colors.danger },
  actions: { flexDirection: "row", alignItems: "center", gap: 12, marginTop: 6 },
  reset: { color: colors.textDim, padding: 10 },
  cancel: { color: colors.textDim, padding: 10 },
  save: { backgroundColor: colors.blue, borderRadius: 10, paddingHorizontal: 20, paddingVertical: 10 },
  saveText: { color: "#fff", fontWeight: "600" },
});
