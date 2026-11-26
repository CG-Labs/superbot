import React from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { PolicyEditor } from "../components/PolicyEditor";
import { kit, Spinner } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** The approval policy (ADR 0049): `/policy` for all Bots, `/policy?bot=<id>` for one. */
export default function PolicyScreen() {
  const styles = useStyles();
  const { ready, api, bots, can } = useSuperBot();
  const { bot: botId } = useLocalSearchParams<{ bot?: string }>();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <Spinner />
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    loading: k.center,
  });
});
