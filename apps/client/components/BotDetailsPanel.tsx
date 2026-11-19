import React, { useEffect, useState } from "react";
import {
  Modal,
  Pressable,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from "react-native";
import { useSuperBot } from "../src/SuperBotContext";
import { colors, HARNESS_NAMES } from "../src/theme";
import type { Routine } from "../src/types";
import { BotAvatar } from "./BotAvatar";

interface Props {
  visible: boolean;
  onClose: () => void;
}

export function BotDetailsPanel({ visible, onClose }: Props) {
  const { bots, activeId, patchBot, deleteBot, fetchRoutines, toggleRoutine, policy, setBotPolicy } = useSuperBot();
  const bot = bots.find((b) => b.id === activeId);
  const [name, setName] = useState(bot?.name || "");
  const [routines, setRoutines] = useState<Routine[]>([]);

  useEffect(() => {
    setName(bot?.name || "");
    if (bot && visible) {
      void fetchRoutines(bot.id).then(setRoutines);
    }
  }, [bot, visible, fetchRoutines]);

  if (!bot) return null;

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <View style={styles.backdrop}>
        <View style={styles.panel}>
          <Pressable style={styles.close} onPress={onClose}>
            <Text style={styles.closeText}>✕</Text>
          </Pressable>
          <BotAvatar color={bot.color} shape={bot.shape} size={90} />
          <TextInput
            style={styles.name}
            value={name}
            onChangeText={setName}
            onBlur={() => {
              const n = name.trim();
              if (n && n !== bot.name) void patchBot(bot.id, { name: n });
            }}
          />
          <Text style={styles.section}>Routines</Text>
          {routines.length ? (
            routines.map((r) => (
              <View key={r.id} style={styles.row}>
                <View style={{ flex: 1 }}>
                  <Text style={styles.rName}>{r.name}</Text>
                  <Text style={styles.rCron}>{r.cron}</Text>
                </View>
                <Switch
                  value={r.enabled}
                  onValueChange={() => void toggleRoutine(r).then(() => fetchRoutines(bot.id).then(setRoutines))}
                />
              </View>
            ))
          ) : (
            <Text style={styles.dim}>No routines yet</Text>
          )}
          <Text style={styles.section}>Settings</Text>
          <View style={styles.row}>
            <Text style={styles.dim}>Runs on {HARNESS_NAMES[bot.harness] || bot.harness}</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.dim}>Hide from sidebar</Text>
            <Switch value={bot.hidden} onValueChange={(v) => void patchBot(bot.id, { hidden: v })} />
          </View>
          <View style={styles.row}>
            <Text style={styles.dim}>Ask before risky actions</Text>
            <Switch
              value={bot.policy !== "bypass"}
              onValueChange={(v) => void setBotPolicy(bot.id, v ? "ask" : "bypass")}
            />
          </View>
          {bot.policyOverride ? (
            <Pressable style={styles.row} onPress={() => void setBotPolicy(bot.id, null)}>
              <Text style={styles.link}>Use the default for all Bots ({policy?.mode ?? "ask"})</Text>
            </Pressable>
          ) : null}
          {!bot.primary ? (
            <Pressable
              style={styles.delete}
              onPress={() => {
                void deleteBot(bot.id);
                onClose();
              }}
            >
              <Text style={styles.deleteText}>Delete bot</Text>
            </Pressable>
          ) : null}
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "flex-end" },
  panel: {
    backgroundColor: colors.bgSidebar,
    borderTopLeftRadius: 16,
    borderTopRightRadius: 16,
    padding: 20,
    maxHeight: "85%",
    gap: 10,
    alignItems: "center",
  },
  close: { alignSelf: "flex-end" },
  closeText: { color: colors.textDim, fontSize: 22 },
  name: {
    color: colors.text,
    fontSize: 22,
    fontWeight: "600",
    textAlign: "center",
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    paddingVertical: 4,
    width: "100%",
  },
  section: { alignSelf: "flex-start", color: colors.textFaint, marginTop: 8 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    width: "100%",
    gap: 10,
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  rName: { color: colors.text },
  rCron: { color: colors.textFaint, fontSize: 13 },
  dim: { color: colors.textDim, flex: 1 },
  link: { color: colors.blueDot, flex: 1 },
  delete: { marginTop: 16, padding: 12 },
  deleteText: { color: colors.danger },
});