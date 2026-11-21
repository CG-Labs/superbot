import React from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { PolicyEditor } from "../components/PolicyEditor";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** The approval policy (ADR 0049): `/policy` for all Bots, `/policy?bot=<id>` for one. */
export default function PolicyScreen() {
  const { ready, api, bots, can } = useSuperBot();
  const { bot: botId } = useLocalSearchParams<{ bot?: string }>();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  const found = botId ? bots.find((b) => b.id === botId) : undefined;
  const bot = botId ? { id: botId, name: found?.name ?? "this Bot" } : undefined;
  const back = () => (router.canGoBack() ? router.back() : router.replace("/home"));
  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      <PolicyEditor key={botId ?? "global"} api={api} bot={bot} canEdit={can("admin")} notifications={api} onBack={back} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
});
