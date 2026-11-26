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
import { harnessChoices } from "../src/plan";
import { useSuperBot } from "../src/SuperBotContext";
import { botColors, botShapes, colors, HARNESS_NAMES } from "../src/theme";
import { BotAvatar } from "./BotAvatar";
import { useModalAnimation } from "./Shell";

interface Props {
  visible: boolean;
  onClose: () => void;
  onCreated: (id: string) => void;
}

export function CreateBotModal({ visible, onClose, onCreated }: Props) {
  const { createBot, harnesses, defaultHarness, me } = useSuperBot();
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
      setError(err instanceof Error ? err.message : "Failed");
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
          <Text style={styles.title}>New bot</Text>
          <BotAvatar color={color} shape={shape} size={100} />
          <TextInput
            style={styles.input}
            placeholder="Name"
            placeholderTextColor={colors.textFaint}
            value={name}
            onChangeText={setName}
          />
          <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.shapeRow}>
            {botShapes.map((s) => (
              <Pressable key={s} onPress={() => setShape(s)}>
                <BotAvatar color={color} shape={s} size={56} ring={s === shape} />
              </Pressable>
            ))}
          </ScrollView>
          <View style={styles.colors}>
            {botColors.map((c) => (
              <Pressable
                key={c}
                style={[styles.colorDot, { backgroundColor: c }, c === color && styles.colorOn]}
                onPress={() => setColor(c)}
              />
            ))}
          </View>
          {choices.map((c) => (
            <Pressable
              key={c.harness}
              style={[styles.harnessRow, harness === c.harness && styles.harnessOn]}
              onPress={() => setPicked(c.isDefault ? null : c.harness)}
            >
              <Text style={styles.harnessText}>{c.label}</Text>
            </Pressable>
          ))}
          {error ? <Text style={styles.error}>{error}</Text> : null}
          <View style={styles.actions}>
            <Pressable onPress={onClose}>
              <Text style={styles.cancel}>Cancel</Text>
            </Pressable>
            <Pressable style={styles.create} onPress={submit} disabled={busy || !name.trim()}>
              <Text style={styles.createText}>Create</Text>
            </Pressable>
          </View>
        </Pressable>
      </Pressable>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.65)",
    justifyContent: "center",
    padding: 20,
  },
  sheet: {
    backgroundColor: colors.bgSidebar,
    borderRadius: 16,
    padding: 20,
    gap: 12,
    alignItems: "center",
    maxWidth: 480,
    width: "100%",
    alignSelf: "center",
  },
  title: { color: colors.text, fontSize: 20, fontWeight: "700", alignSelf: "flex-start" },
  input: {
    width: "100%",
    backgroundColor: colors.bgBubble,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 12,
    color: colors.text,
  },
  shapeRow: { maxHeight: 70 },
  colors: { flexDirection: "row", flexWrap: "wrap", gap: 8, justifyContent: "center" },
  colorDot: { width: 28, height: 28, borderRadius: 14 },
  colorOn: { borderWidth: 2, borderColor: colors.text },
  harnessRow: {
    width: "100%",
    padding: 10,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: colors.border,
  },
  harnessOn: { borderColor: colors.blue, backgroundColor: colors.bgActive },
  harnessText: { color: colors.text },
  error: { color: colors.danger },
  actions: { flexDirection: "row", justifyContent: "space-between", width: "100%" },
  cancel: { color: colors.textDim, padding: 10 },
  create: { backgroundColor: colors.blue, borderRadius: 10, paddingHorizontal: 20, paddingVertical: 10 },
  createText: { color: "#fff", fontWeight: "600" },
});