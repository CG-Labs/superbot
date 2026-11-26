import React, { useState } from "react";
import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { cleanPrompts, MAX_PROMPTS, validatePrompts } from "../src/prompts";
import { friendlyError } from "../src/errors";
import { themedStyles } from "../src/theme";
import { InlineError } from "./ErrorState";
import { kit, usePlaceholder } from "./ui";

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
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const [list, setList] = useState<string[]>(prompts.length ? prompts : [""]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (value: string[] | null) => {
    setBusy(true);
    setError(null);
    try {
      await onSave(value);
    } catch (err) {
      setError(friendlyError(err));
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
            placeholderTextColor={placeholder}
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
            <Text style={styles.removeText} maxFontSizeMultiplier={1.3}>
              ✕
            </Text>
          </Pressable>
        </View>
      ))}
      {list.length < MAX_PROMPTS ? (
        <Pressable role="button" aria-label="Add prompt" disabled={busy} onPress={() => setList((l) => [...l, ""])}>
          <Text style={styles.link}>+ Add prompt</Text>
        </Pressable>
      ) : null}
      {error ? <InlineError message={error} /> : null}
      <View style={styles.actions}>
        {custom ? (
          <Pressable role="button" aria-label="Use the default prompts" disabled={busy} style={styles.ghost} onPress={() => void run(null)}>
            <Text style={styles.ghostText}>Use defaults</Text>
          </Pressable>
        ) : null}
        <View style={styles.end}>
          <Pressable role="button" aria-label="Cancel" disabled={busy} style={styles.ghost} onPress={onCancel}>
            <Text style={styles.ghostText}>Cancel</Text>
          </Pressable>
          <Pressable role="button" aria-label="Save prompts" aria-busy={busy} style={[styles.save, busy && styles.disabled]} disabled={busy} onPress={save}>
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
    hint: k.faint,
    row: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    input: { ...k.input, flex: 1 },
    remove: { padding: t.space.sm },
    removeText: { color: t.c.textMuted, fontSize: 16 },
    link: { ...k.link, paddingVertical: t.space.xs },
    // Wraps so Save stays on the sheet on narrow phones at large text sizes.
    actions: { flexDirection: "row", flexWrap: "wrap", alignItems: "center", gap: t.space.sm, marginTop: t.space.xs },
    end: { flexDirection: "row", flexWrap: "wrap", justifyContent: "flex-end", gap: t.space.sm, marginLeft: "auto" },
    ghost: { ...k.btn, ...k.ghost },
    ghostText: { ...k.btnText, color: t.c.textMuted },
    save: { ...k.btn, ...k.primary },
    saveText: { ...k.btnText, ...k.primaryText },
    disabled: k.disabled,
  });
});
