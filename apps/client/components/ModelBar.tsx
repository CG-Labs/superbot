import React, { useEffect, useState } from "react";
import { Picker } from "@react-native-picker/picker";
import { Platform, StyleSheet, Text, TextInput, View } from "react-native";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles, type, useTheme } from "../src/theme";
import type { ModelOption } from "../src/types";

interface Props {
  botId: string;
  harness: string;
  model?: string | null;
  effort?: string | null;
  /** The Bot's managed plan: only its models are offered (admins). */
  tier?: string;
}

/** On a managed plan the plan picks the model (ADR 0033): people see the plan, not models. */
export function PlanBar({ label }: { label: string }) {
  const styles = useStyles();
  return (
    <View style={styles.row}>
      <Text style={styles.plan} accessibilityLabel="Plan">
        {label} plan · the plan picks the model
      </Text>
    </View>
  );
}

export function ModelBar({ botId, harness, model, effort, tier }: Props) {
  const { fetchModels, patchBot } = useSuperBot();
  const t = useTheme();
  const styles = useStyles();
  const webSelectStyle = {
    flex: 1,
    backgroundColor: t.c.raised,
    color: t.c.textMuted,
    borderRadius: t.radius.pill,
    borderWidth: 1,
    borderStyle: "solid",
    borderColor: t.c.border,
    padding: "5px 12px",
    fontSize: t.font.size.sm,
    fontFamily: t.font.sans,
    outline: "none",
  } as const;
  const [models, setModels] = useState<ModelOption[]>([]);

  useEffect(() => {
    void fetchModels(harness, tier).then(setModels);
  }, [harness, tier, fetchModels]);

  // Typed text belongs to one Bot, so switching Bots never shows or saves another's.
  const [draft, setDraft] = useState({ botId, model, text: model || "" });
  const typed = draft.botId === botId && draft.model === model ? draft.text : model || "";

  const allEfforts = [...new Set(models.flatMap((m) => m.efforts))];
  // An entry without an id: the harness takes any model name, so it is typed, not picked.
  const freeText = models.some((m) => !m.id);
  const options: ModelOption[] = [
    { id: "", label: "Default model", efforts: allEfforts },
    ...models.filter((m) => m.id),
  ];
  const isCurrent = (m: ModelOption) =>
    m.id === (model || "") || (model && m.aliases?.includes(model));
  const current = options.find(isCurrent) ?? options[0];

  const onModel = async (id: string) => {
    const picked = models.find((m) => m.id === id);
    const nextEffort =
      picked && effort && !picked.efforts.includes(effort) ? null : effort;
    await patchBot(botId, { model: id || null, effort: nextEffort ?? null });
  };

  const onEffort = async (e: string) => {
    await patchBot(botId, { effort: e || null });
  };

  const saveTyped = () => {
    if (typed.trim() !== (model || "")) void onModel(typed.trim());
  };
  const onType = (text: string) => setDraft({ botId, model, text });
  const modelField = (
    <TextInput
      style={[styles.picker, styles.input]}
      value={typed}
      onChangeText={onType}
      onSubmitEditing={saveTyped}
      onBlur={saveTyped}
      placeholder="Default model"
      placeholderTextColor={t.c.textFaint}
      autoCapitalize="none"
      autoCorrect={false}
      accessibilityLabel="Model"
    />
  );

  if (Platform.OS === "web") {
    return (
      <View style={styles.row}>
        {freeText ? (
          modelField
        ) : (
          <select
            style={webSelectStyle}
            value={model || ""}
            onChange={(ev) => void onModel(ev.target.value)}
          >
            {options.map((m) => (
              <option key={m.id || "default"} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        )}
        {current.efforts.length ? (
          <select
            style={webSelectStyle}
            value={effort || ""}
            onChange={(ev) => void onEffort(ev.target.value)}
          >
            <option value="">Default effort</option>
            {current.efforts.map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
        ) : null}
      </View>
    );
  }

  return (
    <View style={styles.row}>
      {freeText ? (
        modelField
      ) : (
        <Picker
          selectedValue={model || ""}
          style={styles.picker}
          dropdownIconColor={t.c.text}
          onValueChange={(v) => void onModel(String(v))}
        >
          {options.map((m) => (
            <Picker.Item key={m.id || "default"} label={m.label} value={m.id} color={t.c.text} />
          ))}
        </Picker>
      )}
      {current.efforts.length ? (
        <Picker
          selectedValue={effort || ""}
          style={styles.picker}
          dropdownIconColor={t.c.text}
          onValueChange={(v) => void onEffort(String(v))}
        >
          <Picker.Item label="Default effort" value="" color={t.c.text} />
          {current.efforts.map((e) => (
            <Picker.Item key={e} label={e} value={e} color={t.c.text} />
          ))}
        </Picker>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    row: {
      flexDirection: "row",
      gap: t.space.sm,
      paddingHorizontal: t.space.xs,
      paddingBottom: t.space.sm,
    },
    picker: { flex: 1, color: t.c.text, backgroundColor: t.c.raised },
    plan: { color: t.c.textMuted, ...type(t, "sm"), paddingVertical: t.space.xs, paddingHorizontal: t.space.sm },
    input: {
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.border,
      paddingHorizontal: t.space.md,
      paddingVertical: t.space.xs + 2,
      ...type(t, "sm"),
    },
  }),
);
