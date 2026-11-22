import React, { useEffect, useState } from "react";
import { Modal, StyleSheet, useWindowDimensions, View } from "react-native";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import { ApprovalsInbox } from "../components/ApprovalsInbox";
import { BotDetailsPanel } from "../components/BotDetailsPanel";
import { ChatView } from "../components/ChatView";
import { CreateBotModal } from "../components/CreateBotModal";
import { ScreenViewer } from "../components/ScreenViewer";
import { Sidebar } from "../components/Sidebar";
import { isAdmin, openConsole, openSetup, watchSetup } from "../src/admin";
import { planAvailable } from "../src/billing";
import { showError } from "../src/dialogs";
import { approvalParam } from "../src/notifications";
import { botParam } from "../src/push";
import { isStarter, starterText } from "../src/prompts";
import { useSuperBot } from "../src/SuperBotContext";
import { watchTeamLink } from "../src/team";
import { colors } from "../src/theme";

/** Open screen viewer. `takeOver` tracks whether the user has control; `n` remounts it, e.g. to take over from a handoff card. */
type ScreenState = { takeOver: boolean; n: number } | null;

export default function HomeScreen() {
  const { api, me, bots, activeId, setActiveId, logout, handoffs, fetchScreenUrl, answerQuestion, sendText } = useSuperBot();
  const { width } = useWindowDimensions();
  const wide = width >= 800;
  const [mobilePane, setMobilePane] = useState<"list" | "chat">("list");
  const [createOpen, setCreateOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [screen, setScreen] = useState<ScreenState>(null);
  const [approvalsOpen, setApprovalsOpen] = useState(false);
  // A notification's link: `/home?approval=<id>` (ADR 0061) opens the inbox on it,
  // `/home?bot=<id>` (a finished routine, ADR 0080) opens that Bot's chat.
  const params = useLocalSearchParams<{ approval?: string; bot?: string }>();
  const linked = approvalParam(params.approval);
  const linkedBot = botParam(params.bot);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [setupWaiting, setSetupWaiting] = useState(false);
  const [billing, setBilling] = useState(false);
  const [teamLink, setTeamLink] = useState(false);
  const [prefill, setPrefill] = useState<string | null>(null);

  useEffect(() => (api ? watchSetup(api, me, setSetupWaiting) : undefined), [api, me]);
  useEffect(() => (api ? watchTeamLink(api, setTeamLink) : undefined), [api]);
  useEffect(() => {
    if (!api || !linked) return;
    setFocusId(linked);
    setApprovalsOpen(true);
    router.setParams({ approval: undefined });
  }, [api, linked]);
  useEffect(() => {
    if (!api || !linkedBot || bots.length === 0) return;
    if (bots.some((b) => b.id === linkedBot)) {
      setActiveId(linkedBot);
      if (!wide) setMobilePane("chat");
    }
    router.setParams({ bot: undefined });
  }, [api, linkedBot, bots, wide, setActiveId]);
  useEffect(() => {
    if (!api) return;
    let live = true;
    void planAvailable(api).then((on) => live && setBilling(on));
    return () => {
      live = false;
    };
  }, [api]);

  if (!api) {
    return <Redirect href={linked ? { pathname: "/", params: { approval: linked } } : linkedBot ? { pathname: "/", params: { bot: linkedBot } } : "/"} />;
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

  const runPrompt = (prompt: string) => {
    if (!wide) setMobilePane("chat");
    if (isStarter(prompt)) setPrefill(starterText(prompt));
    else void sendText(prompt).catch((err) => showError(err, "Couldn't send it"));
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
            onOpenPlan={billing ? () => router.push("/plan") : undefined}
            onOpenSecrets={() => router.push("/secrets")}
            onOpenTeam={teamLink ? () => router.push("/team") : undefined}
            onOpenSettings={() => router.push("/settings")}
            onOpenUsers={() => router.push("/users")}
            onOpenAudit={() => router.push("/audit")}
            onOpenAccessReview={() => router.push("/access-review")}
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
            prefill={prefill}
            onPrefilled={() => setPrefill(null)}
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
        onUsePrompt={runPrompt}
        onOpenPolicy={(id) => {
          setDetailsOpen(false);
          router.push({ pathname: "/policy", params: { bot: id } });
        }}
        onOpenAudit={
          isAdmin(me)
            ? (id) => {
                setDetailsOpen(false);
                router.push({ pathname: "/audit", params: { bot: id } });
              }
            : undefined
        }
      />
      <ApprovalsInbox
        visible={approvalsOpen}
        focusId={focusId}
        onClose={() => {
          setApprovalsOpen(false);
          setFocusId(null);
        }}
        onOpenPolicy={() => {
          setApprovalsOpen(false);
          router.push("/policy");
        }}
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  row: { flex: 1, flexDirection: "row" },
  screenPanel: { width: "46%", minWidth: 420, borderLeftWidth: 1, borderLeftColor: colors.border },
  screenModal: { flex: 1, backgroundColor: "#111" },
});
