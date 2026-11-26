import React, { useState } from "react";
import { Pressable, StyleSheet, Switch, Text, TextInput, View } from "react-native";
import { CRON_PRESETS, draftFromRoutine, EMPTY_DRAFT, validateRoutine, type RoutineDraft } from "../src/routines";
import { friendlyError } from "../src/errors";
import { themedStyles, type } from "../src/theme";
import type { Routine } from "../src/types";
import { InlineError } from "./ErrorState";
import { kit, usePlaceholder } from "./ui";

interface Props {
  /** The routine to edit; omit to create one. */
  routine?: Routine;
  onSave: (draft: RoutineDraft) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel: () => void;
}

export function RoutineEditor({ routine, onSave, onDelete, onCancel }: Props) {
  const styles = useStyles();
  const placeholder = usePlaceholder();
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
      setError(friendlyError(err));
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
      <Text style={styles.heading} role="heading">
        {routine ? "Edit routine" : "New routine"}
      </Text>
      <Text style={styles.label}>Name</Text>
      <TextInput
        aria-label="Routine name"
        style={styles.input}
        placeholder="Morning email digest"
        placeholderTextColor={placeholder}
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
              <Text style={[styles.chipText, on && styles.chipTextOn]}>{p.label}</Text>
            </Pressable>
          );
        })}
      </View>
      <TextInput
        aria-label="Cron schedule"
        style={[styles.input, styles.mono]}
        placeholder="0 9 * * 1-5"
        placeholderTextColor={placeholder}
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
        placeholderTextColor={placeholder}
        multiline
        value={draft.instruction}
        onChangeText={(instruction) => set({ instruction })}
      />
      <View style={styles.row}>
        <Text style={styles.rowText}>Enabled</Text>
        <Switch aria-label="Enabled" value={draft.enabled} onValueChange={(enabled) => set({ enabled })} />
      </View>
      {error ? <InlineError message={error} /> : null}
      <View style={styles.actions}>
        {routine && onDelete ? (
          <Pressable
            role="button"
            aria-label="Delete routine"
            disabled={busy}
            style={[styles.delete, busy && styles.disabled]}
            onPress={() => void run(onDelete)}
          >
            <Text style={styles.deleteText}>Delete</Text>
          </Pressable>
        ) : null}
        <View style={styles.end}>
          <Pressable role="button" aria-label="Cancel" disabled={busy} style={styles.cancel} onPress={onCancel}>
            <Text style={styles.cancelText}>Cancel</Text>
          </Pressable>
          <Pressable role="button" aria-label="Save routine" aria-busy={busy} style={[styles.save, busy && styles.disabled]} disabled={busy} onPress={save}>
            <Text style={styles.saveText}>{busy ? "Saving…" : "Save"}</Text>
          </Pressable>
        </View>
      </View>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    form: { width: "100%", gap: t.space.sm },
    heading: k.cardTitle,
    label: { ...k.dim, marginTop: t.space.xs },
    input: k.input,
    mono: { fontFamily: t.font.mono },
    multiline: k.inputMultiline,
    hint: k.faint,
    presets: { flexDirection: "row", flexWrap: "wrap", gap: t.space.xs },
    chip: {
      borderWidth: 1,
      borderColor: t.c.border,
      backgroundColor: t.c.raised,
      borderRadius: t.radius.pill,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.xs,
    },
    chipOn: { backgroundColor: t.c.text, borderColor: t.c.text },
    chipText: { color: t.c.text, ...type(t, "sm") },
    chipTextOn: { color: t.c.bg, fontWeight: t.font.weight.medium },
    row: { flexDirection: "row", alignItems: "center", paddingVertical: t.space.xs },
    rowText: { ...k.text, flex: 1 },
    // Wraps so Save stays on the sheet on narrow phones at large text sizes.
    actions: { flexDirection: "row", flexWrap: "wrap", alignItems: "center", gap: t.space.sm, marginTop: t.space.xs },
    end: { flexDirection: "row", flexWrap: "wrap", justifyContent: "flex-end", gap: t.space.sm, marginLeft: "auto" },
    delete: { ...k.btn, ...k.danger },
    deleteText: { ...k.btnText, ...k.dangerText },
    cancel: { ...k.btn, ...k.ghost },
    cancelText: { ...k.btnText, color: t.c.textMuted },
    save: { ...k.btn, ...k.primary },
    saveText: { ...k.btnText, ...k.primaryText },
    disabled: k.disabled,
  });
});
