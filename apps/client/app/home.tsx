import React, { useEffect, useState } from "react";
import { Modal, StyleSheet, useWindowDimensions, View } from "react-native";
import { Redirect, router } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import { ApprovalsInbox } from "../components/ApprovalsInbox";
import { BotDetailsPanel } from "../components/BotDetailsPanel";
import { ChatView } from "../components/ChatView";
import { CreateBotModal } from "../components/CreateBotModal";
import { ScreenViewer } from "../components/ScreenViewer";
import { Sidebar } from "../components/Sidebar";
import { openConsole, openSetup, watchSetup } from "../src/admin";
import { showError } from "../src/dialogs";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Open screen viewer. `takeOver` tracks whether the user has control; `n` remounts it, e.g. to take over from a handoff card. */
type ScreenState = { takeOver: boolean; n: number } | null;

export default function HomeScreen() {
  const { api, me, bots, activeId, setActiveId, logout, handoffs, fetchScreenUrl, answerQuestion } = useSuperBot();
  const { width } = useWindowDimensions();
  const wide = width >= 800;
  const [mobilePane, setMobilePane] = useState<"list" | "chat">("list");
  const [createOpen, setCreateOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [screen, setScreen] = useState<ScreenState>(null);
  const [approvalsOpen, setApprovalsOpen] = useState(false);
  const [setupWaiting, setSetupWaiting] = useState(false);

  useEffect(() => (api ? watchSetup(api, me, setSetupWaiting) : undefined), [api, me]);

  if (!api) {
    return <Redirect href="/" />;
  }

  const bot = bots.find((b) => b.id === activeId);
  const handoff = bot ? handoffs[bot.id] : undefined;

  const onSelectBot = (id: string) => {
    setActiveId(id);
    setScreen((s) => (s && id !== activeId ? { takeOver: false, n: s.n + 1 } : s));
    if (!wide) setMobilePane("chat");
  };

  const onLogout = () => {
    setScreen(null);
    void logout();
  };

  const toggleScreen = (takeOver?: boolean) => {
    if (takeOver) setScreen((s) => ({ takeOver: true, n: (s?.n ?? 0) + 1 }));
    else setScreen((s) => (s ? null : { takeOver: false, n: 0 }));
  };

  const viewer =
    screen && bot ? (
      <ScreenViewer
        key={`${bot.id}:${screen.n}`}
        botId={bot.id}
        botName={bot.name}
        fetchUrl={fetchScreenUrl}
        initialControl={screen.takeOver}
        handoff={handoff}
        onHandoffDone={
          handoff?.question
            ? () => answerQuestion(handoff, Math.max(0, handoff.question?.options.indexOf("Done") ?? 0))
            : undefined
        }
        onControlChange={(c) => setScreen((s) => (s && s.takeOver !== c ? { ...s, takeOver: c } : s))}
        onClose={() => setScreen(null)}
      />
    ) : null;

  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      <View style={styles.row}>
        {wide || mobilePane === "list" ? (
          <Sidebar
            compact={!wide}
            onSelectBot={onSelectBot}
            onNewBot={() => setCreateOpen(true)}
            onLogout={onLogout}
            onOpenApprovals={() => setApprovalsOpen(true)}
            onOpenUsers={() => router.push("/users")}
            onOpenAudit={() => router.push("/audit")}
            onOpenConsole={() => void openConsole(api.baseUrl).catch((err) => showError(err, "Couldn't open the admin console"))}
            onOpenSetup={
              setupWaiting ? () => void openSetup(api.baseUrl).catch((err) => showError(err, "Couldn't open the setup wizard")) : undefined
            }
          />
        ) : null}
        {wide || mobilePane === "chat" ? (
          <ChatView
            onOpenDetails={() => setDetailsOpen(true)}
            onBack={wide ? undefined : () => setMobilePane("list")}
            onToggleScreen={toggleScreen}
            screenOpen={!!screen}
          />
        ) : null}
        {wide && viewer ? <View style={styles.screenPanel}>{viewer}</View> : null}
      </View>
      {!wide ? (
        <Modal visible={!!viewer} animationType="slide" onRequestClose={() => setScreen(null)}>
          <SafeAreaView style={styles.screenModal}>{viewer}</SafeAreaView>
        </Modal>
      ) : null}
      <CreateBotModal
        visible={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(id) => {
          onSelectBot(id);
        }}
      />
      <BotDetailsPanel
        visible={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        onOpenScreen={() => setScreen((s) => s ?? { takeOver: false, n: 0 })}
      />
      <ApprovalsInbox visible={approvalsOpen} onClose={() => setApprovalsOpen(false)} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  row: { flex: 1, flexDirection: "row" },
  screenPanel: { width: "46%", minWidth: 420, borderLeftWidth: 1, borderLeftColor: colors.border },
  screenModal: { flex: 1, backgroundColor: "#111" },
});
