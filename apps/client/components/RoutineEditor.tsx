import React, { useState } from "react";
import { Pressable, StyleSheet, Switch, Text, TextInput, View } from "react-native";
import { CRON_PRESETS, draftFromRoutine, EMPTY_DRAFT, validateRoutine, type RoutineDraft } from "../src/routines";
import { colors } from "../src/theme";
import type { Routine } from "../src/types";

interface Props {
  /** The routine to edit; omit to create one. */
  routine?: Routine;
  onSave: (draft: RoutineDraft) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel: () => void;
}

export function RoutineEditor({ routine, onSave, onDelete, onCancel }: Props) {
  const [draft, setDraft] = useState<RoutineDraft>(routine ? draftFromRoutine(routine) : EMPTY_DRAFT);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (patch: Partial<RoutineDraft>) => setDraft((d) => ({ ...d, ...patch }));

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  };

  const save = () => {
    const invalid = validateRoutine(draft);
    if (invalid) {
      setError(invalid);
      return;
    }
    void run(() => onSave(draft));
  };

  return (
    <View style={styles.form}>
      <Text style={styles.heading}>{routine ? "Edit routine" : "New routine"}</Text>
      <Text style={styles.label}>Name</Text>
      <TextInput
        aria-label="Routine name"
        style={styles.input}
        placeholder="Morning email digest"
        placeholderTextColor={colors.textFaint}
        value={draft.name}
        maxLength={100}
        onChangeText={(name) => set({ name })}
      />
      <Text style={styles.label}>Schedule</Text>
      <View style={styles.presets}>
        {CRON_PRESETS.map((p) => {
          const on = draft.cron.trim() === p.cron;
          return (
            <Pressable
              key={p.cron}
              role="button"
              aria-label={p.label}
              aria-selected={on}
              style={[styles.chip, on && styles.chipOn]}
              onPress={() => set({ cron: p.cron })}
            >
              <Text style={styles.chipText}>{p.label}</Text>
            </Pressable>
          );
        })}
      </View>
      <TextInput
        aria-label="Cron schedule"
        style={[styles.input, styles.mono]}
        placeholder="0 9 * * 1-5"
        placeholderTextColor={colors.textFaint}
        autoCapitalize="none"
        autoCorrect={false}
        value={draft.cron}
        onChangeText={(cron) => set({ cron })}
      />
      <Text style={styles.hint}>Cron: minute hour day month weekday, in the server&apos;s time zone.</Text>
      <Text style={styles.label}>What to do</Text>
      <TextInput
        aria-label="Instruction"
        style={[styles.input, styles.multiline]}
        placeholder="Summarize my unread email and post the important ones here."
        placeholderTextColor={colors.textFaint}
        multiline
        value={draft.instruction}
        onChangeText={(instruction) => set({ instruction })}
      />
      <View style={styles.row}>
        <Text style={styles.rowText}>Enabled</Text>
        <Switch aria-label="Enabled" value={draft.enabled} onValueChange={(enabled) => set({ enabled })} />
      </View>
      {error ? (
        <Text style={styles.error} role="alert">
          {error}
        </Text>
      ) : null}
      <View style={styles.actions}>
        {routine && onDelete ? (
          <Pressable role="button" aria-label="Delete routine" disabled={busy} onPress={() => void run(onDelete)}>
            <Text style={styles.delete}>Delete</Text>
          </Pressable>
        ) : null}
        <View style={{ flex: 1 }} />
        <Pressable role="button" aria-label="Cancel" disabled={busy} onPress={onCancel}>
          <Text style={styles.cancel}>Cancel</Text>
        </Pressable>
        <Pressable role="button" aria-label="Save routine" style={styles.save} disabled={busy} onPress={save}>
          <Text style={styles.saveText}>{busy ? "Saving…" : "Save"}</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  form: { width: "100%", gap: 8 },
  heading: { color: colors.text, fontSize: 18, fontWeight: "700" },
  label: { color: colors.textFaint, marginTop: 6 },
  input: {
    backgroundColor: colors.bgBubble,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 12,
    color: colors.text,
  },
  mono: { fontFamily: "monospace" },
  multiline: { minHeight: 96, textAlignVertical: "top" },
  hint: { color: colors.textFaint, fontSize: 12 },
  presets: { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  chip: { borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingHorizontal: 12, paddingVertical: 6 },
  chipOn: { borderColor: colors.blue, backgroundColor: colors.bgActive },
  chipText: { color: colors.text, fontSize: 13 },
  row: { flexDirection: "row", alignItems: "center", paddingVertical: 6 },
  rowText: { color: colors.text, flex: 1 },
  error: { color: colors.danger },
  actions: { flexDirection: "row", alignItems: "center", gap: 12, marginTop: 6 },
  delete: { color: colors.danger, padding: 10 },
  cancel: { color: colors.textDim, padding: 10 },
  save: { backgroundColor: colors.blue, borderRadius: 10, paddingHorizontal: 20, paddingVertical: 10 },
  saveText: { color: "#fff", fontWeight: "600" },
});
