import React, { useEffect, useRef, useState } from "react";
import {
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from "react-native";
import { sharingLabel, whereItRuns, whoseKeys } from "../src/access";
import { confirmAsync, showError } from "../src/dialogs";
import { cronLabel } from "../src/routines";
import { useSuperBot } from "../src/SuperBotContext";
import { colors, HARNESS_NAMES } from "../src/theme";
import type { Routine } from "../src/types";
import { BotAvatar } from "./BotAvatar";
import { Chips } from "./Chips";
import { RoutineEditor } from "./RoutineEditor";

interface Props {
  visible: boolean;
  onClose: () => void;
  onOpenScreen: () => void;
}

/** "new" or the routine being edited; null shows the details. */
type Editing = "new" | Routine | null;

export function BotDetailsPanel({ visible, onClose, onOpenScreen }: Props) {
  const {
    bots,
    activeId,
    patchBot,
    deleteBot,
    fetchRoutines,
    toggleRoutine,
    createRoutine,
    updateRoutine,
    deleteRoutine,
    policy,
    setBotPolicy,
    setBotVisibility,
    can,
    canOnBot,
    me,
    harnesses,
  } = useSuperBot();
  const bot = bots.find((b) => b.id === activeId);
  // The Bot's own harness stays listed even if it is no longer installed. Admins get
  // the owner's plan's harnesses on the Bot itself.
  const harnessChoices = bot ? [...new Set([...(bot.harnesses ?? harnesses ?? []), bot.harness])] : [];
  const canOperate = canOnBot(bot, "operate");
  const canManage = canOnBot(bot, "manage");
  const botId = bot?.id;
  const [name, setName] = useState(bot?.name || "");
  const [routines, setRoutines] = useState<Routine[]>([]);
  const [editing, setEditing] = useState<Editing>(null);
  /** The Bot whose routines are on screen; a load for any other (or a closed panel) is stale. */
  const shownRef = useRef<string | null>(null);

  const showRoutines = (id: string, list: Routine[]) => {
    if (shownRef.current === id) setRoutines(list.filter((r) => r.bot_id === id));
  };

  useEffect(() => {
    setName(bot?.name || "");
  }, [bot?.name]);

  useEffect(() => {
    setEditing(null);
    setRoutines([]);
    shownRef.current = botId && visible ? botId : null;
    if (botId && visible) {
      void fetchRoutines(botId)
        .then((list) => showRoutines(botId, list))
        .catch(() => showRoutines(botId, []));
    }
    // fetchRoutines changes identity on every provider render; reload only when the Bot or visibility changes.
  }, [botId, visible]);

  if (!bot) return null;

  const reload = () => {
    const id = bot.id;
    return fetchRoutines(id).then((list) => showRoutines(id, list));
  };

  const close = () => {
    setEditing(null);
    onClose();
  };

  const editor =
    editing === null ? null : (
      <RoutineEditor
        key={editing === "new" ? "new" : editing.id}
        routine={editing === "new" ? undefined : editing}
        onCancel={() => setEditing(null)}
        onSave={async (draft) => {
          if (editing === "new") await createRoutine(bot.id, draft);
          else await updateRoutine(editing, draft);
          await reload();
          setEditing(null);
        }}
        onDelete={
          editing === "new"
            ? undefined
            : async () => {
                const ok = await confirmAsync(`Delete "${editing.name}"?`, "The Bot stops running it.");
                if (!ok) return;
                await deleteRoutine(editing.id);
                await reload();
                setEditing(null);
              }
        }
      />
    );

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={close}>
      <View style={styles.backdrop}>
        <ScrollView style={styles.panel} contentContainerStyle={styles.panelContent}>
          <Pressable style={styles.close} role="button" aria-label="Close details" onPress={close}>
            <Text style={styles.closeText}>✕</Text>
          </Pressable>
          {editor ?? (
          <>
          <BotAvatar color={bot.color} shape={bot.shape} size={90} />
          <TextInput
            style={styles.name}
            value={name}
            editable={canManage}
            onChangeText={setName}
            onBlur={() => {
              const n = name.trim();
              if (n && n !== bot.name) void patchBot(bot.id, { name: n });
            }}
          />
          <View style={styles.sectionRow}>
            <Text style={styles.sectionLabel}>Routines</Text>
            {canOperate ? (
              <Pressable role="button" aria-label="New routine" onPress={() => setEditing("new")}>
                <Text style={styles.link}>+ New routine</Text>
              </Pressable>
            ) : null}
          </View>
          {routines.length ? (
            routines.map((r) => (
              <View key={r.id} style={styles.row}>
                <Pressable
                  style={{ flex: 1 }}
                  role="button"
                  aria-label={`Edit routine ${r.name}`}
                  disabled={!canOperate}
                  onPress={() => setEditing(r)}
                >
                  <Text style={styles.rName}>{r.name}</Text>
                  <Text style={styles.rCron}>{cronLabel(r.cron)}</Text>
                </Pressable>
                <Switch
                  aria-label={r.enabled ? `Pause ${r.name}` : `Resume ${r.name}`}
                  value={r.enabled}
                  disabled={!canOperate}
                  onValueChange={() => void toggleRoutine(r).then(reload).catch(showError)}
                />
              </View>
            ))
          ) : (
            <Text style={styles.dim}>No routines yet</Text>
          )}
          <Text style={styles.section}>Computer</Text>
          <View style={styles.row}>
            <Text style={styles.dim}>{bot.working ? bot.status || "Working" : "Asleep"}</Text>
            {canOperate ? (
              <Pressable
                role="button"
                aria-label="Open screen"
                onPress={() => {
                  close();
                  onOpenScreen();
                }}
              >
                <Text style={styles.link}>Open screen</Text>
              </Pressable>
            ) : null}
          </View>
          <Text style={styles.section}>Settings</Text>
          <View style={styles.row}>
            <Text style={styles.dim}>Runs on {HARNESS_NAMES[bot.harness] || bot.harness}</Text>
          </View>
          {canManage && harnessChoices.length > 1 ? (
            <View style={styles.harnessPick}>
              <Chips
                options={harnessChoices.map((h) => ({ value: h, label: HARNESS_NAMES[h] || h }))}
                value={bot.harness}
                onChange={(h) => {
                  if (h !== bot.harness) void patchBot(bot.id, { harness: h }).catch(showError);
                }}
              />
            </View>
          ) : null}
          <View style={styles.row}>
            <Text style={styles.dim}>Hide from sidebar</Text>
            <Switch value={bot.hidden} disabled={!canManage} onValueChange={(v) => void patchBot(bot.id, { hidden: v })} />
          </View>
          <View style={styles.row}>
            <Text style={styles.dim}>Ask before risky actions</Text>
            <Switch
              value={bot.policy !== "bypass"}
              disabled={!can("admin")}
              onValueChange={(v) => void setBotPolicy(bot.id, v ? "ask" : "bypass")}
            />
          </View>
          {bot.policyOverride && can("admin") ? (
            <Pressable style={styles.row} onPress={() => void setBotPolicy(bot.id, null)}>
              <Text style={styles.policyLink}>Use the default for all Bots ({policy?.mode ?? "ask"})</Text>
            </Pressable>
          ) : null}
          {bot.visibility ? (
            <>
              <Text style={styles.section}>Sharing</Text>
              <View style={styles.row}>
                <Text style={styles.dim}>{sharingLabel(bot, me.id)}</Text>
              </View>
              {[whereItRuns(bot, me.id), whoseKeys(bot, me.id)].filter(Boolean).map((line) => (
                <View key={line} style={styles.row}>
                  <Text style={styles.dim}>{line}</Text>
                </View>
              ))}
              <View style={styles.row}>
                <Text style={styles.dim}>Shared with everyone</Text>
                <Switch
                  aria-label={bot.visibility === "shared" ? "Make private" : "Share with everyone"}
                  value={bot.visibility === "shared"}
                  disabled={!canManage}
                  onValueChange={(v) => void setBotVisibility(bot.id, v ? "shared" : "private").catch(showError)}
                />
              </View>
            </>
          ) : null}
          {!bot.primary && canManage ? (
            <Pressable
              style={styles.delete}
              onPress={() => {
                void confirmAsync(
                  `Delete ${bot.name}?`,
                  "This erases its chat, memory, and routines. Files on the computer stay.",
                ).then((ok) => {
                  if (!ok) return;
                  void deleteBot(bot.id);
                  onClose();
                });
              }}
            >
              <Text style={styles.deleteText}>Delete bot</Text>
            </Pressable>
          ) : null}
          </>
          )}
        </ScrollView>
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
    maxHeight: "85%",
    flexGrow: 0,
  },
  panelContent: { padding: 20, gap: 10, alignItems: "center" },
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
  sectionRow: { flexDirection: "row", alignItems: "center", width: "100%", marginTop: 8 },
  sectionLabel: { color: colors.textFaint, flex: 1 },
  link: { color: colors.blueDot },
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
  policyLink: { color: colors.blueDot, flex: 1 },
  harnessPick: { width: "100%", paddingVertical: 8 },
  delete: { marginTop: 16, padding: 12 },
  deleteText: { color: colors.danger },
});