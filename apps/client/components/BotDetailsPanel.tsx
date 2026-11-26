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
import { keptBy, sharingLabel, whereItRuns, whoseKeys } from "../src/access";
import { confirmAsync, showError } from "../src/dialogs";
import { errorText } from "../src/errors";
import { useReducedMotion } from "../src/motion";
import { promptsFor } from "../src/prompts";
import { cronLabel } from "../src/routines";
import { workingLabel } from "../src/runQueue";
import { useSuperBot } from "../src/SuperBotContext";
import { hairline, HARNESS_NAMES, themedStyles, type } from "../src/theme";
import type { Routine } from "../src/types";
import { BotAvatar } from "./BotAvatar";
import { Chips } from "./Chips";
import { EmptyState } from "./EmptyState";
import { InlineError } from "./ErrorState";
import { KeeperPanel } from "./KeeperPanel";
import { PromptsEditor } from "./PromptsEditor";
import { RoutineEditor } from "./RoutineEditor";
import { ListSkeleton } from "./Skeleton";
import { SuggestedPrompts } from "./SuggestedPrompts";
import { TeammateLoginPanel } from "./TeammateLoginPanel";
import { kit } from "./ui";

interface Props {
  visible: boolean;
  onClose: () => void;
  onOpenScreen: () => void;
  /** Opens this Bot's policy editor (ADR 0049). */
  onOpenPolicy?: (botId: string) => void;
  /** Admins only: opens the audit log filtered to this Bot (ADR 0060). */
  onOpenAudit?: (botId: string) => void;
  /** Sends a suggested prompt to this Bot, or puts a starter in its message box (ADR 0054). */
  onUsePrompt?: (prompt: string) => void;
}

/** "new" or the routine being edited, or "prompts"; null shows the details. */
type Editing = "new" | "prompts" | Routine | null;

export function BotDetailsPanel({ visible, onClose, onOpenScreen, onOpenPolicy, onOpenAudit, onUsePrompt }: Props) {
  const styles = useStyles();
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
    api,
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
  /** Whether the shown Bot's routines are still loading, or why they couldn't. */
  const [routinesState, setRoutinesState] = useState<{ loading: boolean; error: string | null }>({ loading: false, error: null });
  const reduceMotion = useReducedMotion();
  const [editing, setEditingState] = useState<Editing>(null);
  /** Bumped whenever the form changes, so a save that finishes late can't close a newer one. */
  const sessionRef = useRef(0);
  const setEditing = (e: Editing) => {
    sessionRef.current += 1;
    setEditingState(e);
  };
  /** The Bot whose routines are on screen; a load for any other (or a closed panel) is stale. */
  const shownRef = useRef<string | null>(null);

  const showRoutines = (id: string, list: Routine[]) => {
    if (shownRef.current !== id) return;
    setRoutines(list.filter((r) => r.bot_id === id));
    setRoutinesState({ loading: false, error: null });
  };
  const loadRoutines = (id: string) => {
    setRoutinesState({ loading: true, error: null });
    return fetchRoutines(id)
      .then((list) => showRoutines(id, list))
      .catch((err) => {
        if (shownRef.current === id) setRoutinesState({ loading: false, error: errorText(err, "Couldn't load routines") });
      });
  };

  useEffect(() => {
    setName(bot?.name || "");
  }, [bot?.name]);

  useEffect(() => {
    setEditing(null);
    setRoutines([]);
    shownRef.current = botId && visible ? botId : null;
    if (botId && visible) void loadRoutines(botId);
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

  const prompts = promptsFor(bot);

  const editor =
    editing === null ? null : editing === "prompts" ? (
      <PromptsEditor
        prompts={prompts}
        custom={bot.prompts != null}
        onCancel={() => setEditing(null)}
        onSave={async (list) => {
          const session = sessionRef.current;
          await patchBot(bot.id, { prompts: list });
          if (sessionRef.current === session) setEditing(null);
        }}
      />
    ) : (
      <RoutineEditor
        key={editing === "new" ? "new" : editing.id}
        routine={editing === "new" ? undefined : editing}
        onCancel={() => setEditing(null)}
        onSave={async (draft) => {
          const session = sessionRef.current;
          if (editing === "new") await createRoutine(bot.id, draft);
          else await updateRoutine(editing, draft);
          await reload();
          if (sessionRef.current === session) setEditing(null);
        }}
        onDelete={
          editing === "new"
            ? undefined
            : async () => {
                const ok = await confirmAsync(`Delete "${editing.name}"?`, "The Bot stops running it.");
                if (!ok) return;
                const session = sessionRef.current;
                await deleteRoutine(editing.id);
                await reload();
                if (sessionRef.current === session) setEditing(null);
              }
        }
      />
    );

  return (
    <Modal visible={visible} animationType={reduceMotion ? "none" : "slide"} transparent onRequestClose={close}>
      <View style={styles.backdrop}>
        <ScrollView style={styles.panel} contentContainerStyle={styles.panelContent} testID="bot-details">
          <Pressable style={styles.close} role="button" aria-label="Close details" onPress={close}>
            <Text style={styles.closeText} maxFontSizeMultiplier={1.3}>
              ✕
            </Text>
          </Pressable>
          {editor ?? (
          <>
          <BotAvatar color={bot.color} shape={bot.shape} size={90} />
          <TextInput
            style={styles.name}
            aria-label="Bot name"
            value={name}
            editable={canManage}
            onChangeText={setName}
            onBlur={() => {
              const n = name.trim();
              if (n && n !== bot.name) void patchBot(bot.id, { name: n });
            }}
          />
          {canOperate && onUsePrompt ? (
            <SuggestedPrompts
              botName={bot.name}
              prompts={prompts}
              onUse={(p) => {
                close();
                onUsePrompt(p);
              }}
              onEdit={canManage ? () => setEditing("prompts") : undefined}
            />
          ) : null}
          <View style={styles.sectionRow}>
            <Text style={styles.sectionLabel} role="heading">
              Routines
            </Text>
            {canOperate ? (
              <Pressable role="button" aria-label="New routine" onPress={() => setEditing("new")}>
                <Text style={styles.link}>+ New routine</Text>
              </Pressable>
            ) : null}
          </View>
          {routinesState.loading && !routines.length ? (
            <View style={styles.state}>
              <ListSkeleton label="Loading routines" rows={2} />
            </View>
          ) : routinesState.error ? (
            <View style={styles.state}>
              <InlineError message={routinesState.error} onRetry={() => loadRoutines(bot.id)} />
            </View>
          ) : routines.length ? (
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
            <EmptyState compact glyph="+" title="No routines yet" message={`Routines run on a schedule, like a morning summary from ${bot.name}.`} />
          )}
          <Text style={styles.section} role="heading">
            Computer
          </Text>
          <View style={styles.row}>
            <Text style={styles.dim}>{bot.working ? workingLabel(bot) : "Asleep"}</Text>
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
          <Text style={styles.section} role="heading">
            Settings
          </Text>
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
            <Switch
              aria-label="Hide from sidebar"
              value={bot.hidden}
              disabled={!canManage}
              onValueChange={(v) => void patchBot(bot.id, { hidden: v })}
            />
          </View>
          <View style={styles.row}>
            <Text style={styles.dim}>Ask before risky actions</Text>
            <Switch
              aria-label="Ask before risky actions"
              value={bot.policy !== "bypass"}
              disabled={!can("admin")}
              onValueChange={(v) => void setBotPolicy(bot.id, v ? "ask" : "bypass")}
            />
          </View>
          {bot.policyOverride && can("admin") ? (
            <Pressable
              style={styles.row}
              role="button"
              aria-label={`Use the default for all Bots (${policy?.mode ?? "ask"})`}
              onPress={() => void setBotPolicy(bot.id, null)}
            >
              <Text style={styles.policyLink}>Use the default for all Bots ({policy?.mode ?? "ask"})</Text>
            </Pressable>
          ) : null}
          {onOpenPolicy ? (
            <Pressable style={styles.row} role="button" aria-label="Approval policy" onPress={() => onOpenPolicy(bot.id)}>
              <Text style={styles.policyLink}>{can("admin") ? "Edit risky actions, timeout, and rules ›" : "See risky actions, timeout, and rules ›"}</Text>
            </Pressable>
          ) : null}
          {onOpenAudit ? (
            <Pressable style={styles.row} role="button" aria-label="Audit log for this Bot" onPress={() => onOpenAudit(bot.id)}>
              <Text style={styles.policyLink}>Approvals and changes in the audit log ›</Text>
            </Pressable>
          ) : null}
          {bot.visibility ? (
            <>
              <Text style={styles.section} role="heading">
                Sharing
              </Text>
              <View style={styles.row}>
                <Text style={styles.dim}>{sharingLabel(bot, me.id)}</Text>
              </View>
              {[keptBy(bot), whereItRuns(bot, me.id), whoseKeys(bot, me.id)].filter(Boolean).map((line) => (
                <View key={line} style={styles.row}>
                  <Text style={styles.dim}>{line}</Text>
                </View>
              ))}
              {api && bot.teammateLogins && bot.owner && bot.owner.id !== me.id && canOperate ? (
                <TeammateLoginPanel
                  key={`${bot.owner.id}:${bot.harness}`}
                  api={api}
                  ownerId={bot.owner.id}
                  ownerName={bot.owner.name || "its owner"}
                  harness={bot.harness}
                  canWrite={can("write")}
                />
              ) : null}
              <View style={styles.row}>
                <Text style={styles.dim}>Shared with everyone</Text>
                <Switch
                  aria-label={bot.visibility === "shared" ? "Make private" : "Share with everyone"}
                  value={bot.visibility === "shared"}
                  disabled={!canManage}
                  onValueChange={(v) => void setBotVisibility(bot.id, v ? "shared" : "private").catch(showError)}
                />
              </View>
              {api && canManage && !bot.primary && (bot.owner?.id === me.id || can("admin")) ? (
                <KeeperPanel key={bot.id} api={api} botId={bot.id} botName={bot.name} keptBy={bot.serviceAccount?.id ?? null} />
              ) : null}
            </>
          ) : null}
          {!bot.primary && canManage ? (
            <Pressable
              style={({ pressed }) => [styles.delete, pressed && styles.pressed]}
              role="button"
              aria-label="Delete bot"
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    backdrop: { flex: 1, backgroundColor: t.c.overlay, justifyContent: "flex-end" },
    panel: {
      backgroundColor: t.c.surface,
      borderTopLeftRadius: t.radius.xl,
      borderTopRightRadius: t.radius.xl,
      maxHeight: "85%",
      flexGrow: 0,
    },
    panelContent: { padding: t.space.xl, gap: t.space.sm, alignItems: "center" },
    close: { alignSelf: "flex-end" },
    closeText: { color: t.c.textMuted, fontSize: 22 },
    name: {
      color: t.c.text,
      ...type(t, "xl"),
      fontWeight: t.font.weight.semibold,
      textAlign: "center",
      borderBottomWidth: hairline,
      borderBottomColor: t.c.border,
      paddingVertical: t.space.xs,
      width: "100%",
    },
    section: { alignSelf: "flex-start", color: t.c.textMuted, ...type(t, "sm"), fontWeight: t.font.weight.semibold, marginTop: t.space.sm },
    sectionRow: { flexDirection: "row", alignItems: "center", width: "100%", marginTop: t.space.sm },
    sectionLabel: { color: t.c.textMuted, ...type(t, "sm"), fontWeight: t.font.weight.semibold, flex: 1 },
    link: k.link,
    row: {
      flexDirection: "row",
      alignItems: "center",
      width: "100%",
      gap: t.space.sm,
      paddingVertical: t.space.sm,
      borderBottomWidth: hairline,
      borderBottomColor: t.c.border,
    },
    rName: k.text,
    rCron: { color: t.c.textMuted, ...type(t, "sm") },
    dim: { color: t.c.textMuted, ...type(t, "md"), flex: 1 },
    policyLink: { ...k.link, flex: 1 },
    harnessPick: { width: "100%", paddingVertical: t.space.sm },
    state: { width: "100%", paddingVertical: t.space.sm },
    delete: { ...k.btn, ...k.danger, marginTop: t.space.lg },
    deleteText: { ...k.btnText, ...k.dangerText },
    pressed: { opacity: 0.7 },
  });
});
