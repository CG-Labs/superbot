import React, { useState } from "react";
import { StyleSheet, useWindowDimensions, View } from "react-native";
import { Redirect } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import { ApprovalsInbox } from "../components/ApprovalsInbox";
import { BotDetailsPanel } from "../components/BotDetailsPanel";
import { ChatView } from "../components/ChatView";
import { CreateBotModal } from "../components/CreateBotModal";
import { Sidebar } from "../components/Sidebar";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

export default function HomeScreen() {
  const { api, setActiveId, logout } = useSuperBot();
  const { width } = useWindowDimensions();
  const wide = width >= 800;
  const [mobilePane, setMobilePane] = useState<"list" | "chat">("list");
  const [createOpen, setCreateOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [approvalsOpen, setApprovalsOpen] = useState(false);

  if (!api) {
    return <Redirect href="/" />;
  }

  const onSelectBot = (id: string) => {
    setActiveId(id);
    if (!wide) setMobilePane("chat");
  };

  const onLogout = () => {
    void logout();
  };

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
          />
        ) : null}
        {wide || mobilePane === "chat" ? (
          <ChatView
            onOpenDetails={() => setDetailsOpen(true)}
            onBack={wide ? undefined : () => setMobilePane("list")}
          />
        ) : null}
      </View>
      <CreateBotModal
        visible={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(id) => {
          onSelectBot(id);
        }}
      />
      <BotDetailsPanel visible={detailsOpen} onClose={() => setDetailsOpen(false)} />
      <ApprovalsInbox visible={approvalsOpen} onClose={() => setApprovalsOpen(false)} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  row: { flex: 1, flexDirection: "row" },
});