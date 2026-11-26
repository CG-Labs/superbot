import React, { useState } from "react";
import {
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { friendlyError } from "../src/errors";
import { harnessChoices } from "../src/plan";
import { useSuperBot } from "../src/SuperBotContext";
import { botColorNames, botColors, botShapes, HARNESS_NAMES, themedStyles, type } from "../src/theme";
import { InlineError } from "./ErrorState";
import { kit, usePlaceholder } from "./ui";
import { BotAvatar } from "./BotAvatar";
import { useModalAnimation } from "./Shell";

interface Props {
  visible: boolean;
  onClose: () => void;
  onCreated: (id: string) => void;
}

export function CreateBotModal({ visible, onClose, onCreated }: Props) {
  const { createBot, harnesses, defaultHarness, me } = useSuperBot();
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const [name, setName] = useState("");
  const [color, setColor] = useState(botColors[0]);
  const [shape, setShape] = useState(botShapes[0]);
  // Null until the user picks one: the server then gives the plan's default.
  const [picked, setPicked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const modalAnimation = useModalAnimation();

  const submit = async () => {
    const n = name.trim();
    if (!n) return;
    setBusy(true);
    setError(null);
    try {
      const b = await createBot({ name: n, color, shape, harness: picked ?? undefined });
      setName("");
      setPicked(null);
      onCreated(b.id);
      onClose();
    } catch (err) {
      setError(friendlyError(err, "Couldn't create the Bot. Try again."));
    } finally {
      setBusy(false);
    }
  };

  const choices = harnessChoices(defaultHarness, harnesses, !!me.tier?.managed, HARNESS_NAMES);
  const harness = picked ?? defaultHarness;

  return (
    <Modal visible={visible} animationType={modalAnimation} transparent onRequestClose={onClose}>
      <Pressable style={styles.backdrop} onPress={onClose}>
        <Pressable style={styles.sheet} onPress={(e) => e.stopPropagation()}>
          <Text style={styles.title} role="heading">
            New bot
          </Text>
          <BotAvatar color={color} shape={shape} size={100} />
          <TextInput
            style={styles.input}
            placeholder="Name"
            placeholderTextColor={placeholder}
            accessibilityLabel="Bot name"
            value={name}
            onChangeText={setName}
          />
          <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.shapeRow}>
            {botShapes.map((s) => (
              <Pressable
                key={s}
                accessibilityRole="button"
                accessibilityLabel={`Shape ${s}`}
                accessibilityState={{ selected: s === shape }}
                onPress={() => setShape(s)}
              >
                <BotAvatar color={color} shape={s} size={56} ring={s === shape} />
              </Pressable>
            ))}
          </ScrollView>
          <View style={styles.colors}>
            {botColors.map((c, i) => (
              <Pressable
                key={c}
                accessibilityRole="button"
                accessibilityLabel={`Colour ${botColorNames[i] ?? i + 1}`}
                accessibilityState={{ selected: c === color }}
                style={[styles.colorDot, { backgroundColor: c }, c === color && styles.colorOn]}
                onPress={() => setColor(c)}
              />
            ))}
          </View>
          <View style={styles.harnesses} accessibilityRole="radiogroup" accessibilityLabel="Harness">
            {choices.map((c) => {
              const on = harness === c.harness;
              return (
                <Pressable
                  key={c.harness}
                  accessibilityRole="radio"
                  accessibilityState={{ checked: on }}
                  style={({ pressed }) => [styles.harnessRow, pressed && !on && styles.pressed, on && styles.harnessOn]}
                  onPress={() => setPicked(c.isDefault ? null : c.harness)}
                >
                  <Text style={styles.harnessText}>{c.label}</Text>
                </Pressable>
              );
            })}
          </View>
          {error ? <InlineError message={error} /> : null}
          <View style={styles.actions}>
            <Pressable accessibilityRole="button" style={({ pressed }) => [styles.cancel, pressed && styles.pressed]} onPress={onClose}>
              <Text style={styles.cancelText}>Cancel</Text>
            </Pressable>
            <Pressable
              accessibilityRole="button"
              accessibilityState={{ disabled: busy || !name.trim(), busy }}
              aria-busy={busy}
              style={({ pressed }) => [styles.create, pressed && { opacity: 0.7 }, (busy || !name.trim()) && styles.disabled]}
              onPress={submit}
              disabled={busy || !name.trim()}
            >
              <Text style={styles.createText}>{busy ? "Creating…" : "Create"}</Text>
            </Pressable>
          </View>
        </Pressable>
      </Pressable>
    </Modal>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    backdrop: k.backdrop,
    sheet: { ...k.sheet, ...k.sheetBody, maxWidth: 480, alignItems: "center" },
    title: { ...k.cardTitle, ...type(t, "xl"), fontWeight: t.font.weight.bold, alignSelf: "flex-start" },
    input: { ...k.input, width: "100%" },
    shapeRow: { maxHeight: 70 },
    colors: { flexDirection: "row", flexWrap: "wrap", gap: t.space.sm, justifyContent: "center" },
    colorDot: { width: 28, height: 28, borderRadius: 14 },
    colorOn: { borderWidth: 2, borderColor: t.c.text },
    harnesses: { width: "100%", gap: t.space.sm },
    harnessRow: {
      width: "100%",
      paddingVertical: 10,
      paddingHorizontal: t.space.md,
      borderRadius: t.radius.md,
      borderWidth: 1,
      borderColor: t.c.border,
    },
    harnessOn: { borderColor: t.c.accentBorder, backgroundColor: t.c.selected },
    harnessText: k.text,
    pressed: { backgroundColor: t.c.hover },
    actions: { flexDirection: "row", justifyContent: "space-between", width: "100%" },
    cancel: { ...k.btn, ...k.ghost },
    cancelText: { ...k.btnText, ...k.ghostText },
    create: { ...k.btn, ...k.primary },
    createText: { ...k.btnText, ...k.primaryText },
    disabled: k.disabled,
  });
});
